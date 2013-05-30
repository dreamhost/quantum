# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Dan Wendlandt, Nicira, Inc
#

import netaddr
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.sql import expression as expr

from quantum.api.rpc.agentnotifiers import l3_rpc_agent_api
from quantum.api.v2 import attributes
from quantum.common import constants as l3_constants
from quantum.common import exceptions as q_exc
from quantum.db import db_base_plugin_v2
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import l3
from quantum.openstack.common import log as logging
from quantum.openstack.common.notifier import api as notifier_api
from quantum.openstack.common import uuidutils
from quantum import policy


LOG = logging.getLogger(__name__)


DEVICE_OWNER_ROUTER_INTF = l3_constants.DEVICE_OWNER_ROUTER_INTF
DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_FLOATINGIP = l3_constants.DEVICE_OWNER_FLOATINGIP

# Maps API field to DB column
# API parameter name and Database column names may differ.
# Useful to keep the filtering between API and Database.
API_TO_DB_COLUMN_MAP = {'port_id': 'fixed_port_id'}


class RouterPort(model_base.BASEV2, models_v2.HasId):
    router_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('routers.id', ondelete="CASCADE"),
        primary_key=True)
    port_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ports.id', ondelete="CASCADE"),
        primary_key=True)
    port_type = sa.Column(sa.String(255), nullable=False)
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref('routerport', uselist=False, cascade="all,delete"))


class Router(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 quantum router."""
    name = sa.Column(sa.String(255))
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    gw_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id', ondelete='CASCADE'))
    gw_port = orm.relationship(models_v2.Port)
    attached_ports = orm.relationship(
        RouterPort,
        backref='router', lazy='dynamic')


class FloatingIP(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a floating IP, which may or many not be
       allocated to a tenant, and may or may not be associated with
       an internal port/ip address/router.
    """
    floating_ip_address = sa.Column(sa.String(64), nullable=False)
    floating_network_id = sa.Column(sa.String(36), nullable=False)
    floating_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'),
                                 nullable=False)
    fixed_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    fixed_ip_address = sa.Column(sa.String(64))
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'))
    router = orm.relationship(Router, backref='floating_ips')


class ExternalNetwork(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)


class L3_NAT_db_mixin(l3.RouterPluginBase):
    """Mixin class to add L3/NAT router methods to db_plugin_base_v2"""

    def _network_model_hook(self, context, original_model, query):
        query = query.outerjoin(ExternalNetwork,
                                (original_model.id ==
                                 ExternalNetwork.network_id))
        return query

    def _network_filter_hook(self, context, original_model, conditions):
        if conditions is not None and not hasattr(conditions, '__iter__'):
            conditions = (conditions, )
        # Apply the external network filter only in non-admin context
        if not context.is_admin and hasattr(original_model, 'tenant_id'):
            conditions = expr.or_(ExternalNetwork.network_id != expr.null(),
                                  *conditions)
        return conditions

    def _network_result_filter_hook(self, query, filters):
        vals = filters and filters.get('router:external', [])
        if not vals:
            return query
        if vals[0]:
            return query.filter((ExternalNetwork.network_id != expr.null()))
        return query.filter((ExternalNetwork.network_id == expr.null()))

    # TODO(salvatore-orlando): Perform this operation without explicitly
    # referring to db_base_plugin_v2, as plugins that do not extend from it
    # might exist in the future
    db_base_plugin_v2.QuantumDbPluginV2.register_model_query_hook(
        models_v2.Network,
        "external_net",
        _network_model_hook,
        _network_filter_hook,
        _network_result_filter_hook)

    def _get_router(self, context, id):
        try:
            router = self._get_by_id(context, Router, id)
        except exc.NoResultFound:
            raise l3.RouterNotFound(router_id=id)
        except exc.MultipleResultsFound:
            LOG.error(_('Multiple routers match for %s'), id)
            raise l3.RouterNotFound(router_id=id)
        return router

    def _make_router_dict(self, router, fields=None, depth=0):
        res = {'id': router['id'],
               'name': router['name'],
               'tenant_id': router['tenant_id'],
               'admin_state_up': router['admin_state_up'],
               'status': router['status'],
               'external_gateway_info': None}

        if router['gw_port_id']:
            nw_id = router.gw_port['network_id']
            res['external_gateway_info'] = {'network_id': nw_id}

        if depth:
            if router.gw_port:
                res['gw_port'] = self._make_port_dict(router.gw_port,
                                                      depth=depth-1)
            else:
                res['gw_port'] = None

            res['ports'] = [
                self._make_port_dict(rp.port, depth=depth-1)
                for rp in router['attached_ports'].all()
            ]

            res['floatingips'] = [
                self._make_floatingip_dict(floatingip)
                for floatingip in router.floating_ips
            ]
        return self._fields(res, fields)

    def create_router(self, context, router):
        r = router['router']
        gw_info = r.pop('external_gateway_info', None)
        tenant_id = self._get_tenant_id_for_create(context, r)
        with context.session.begin(subtransactions=True):
            # pre-generate id so it will be available when
            # configuring external gw port
            router_obj = Router(id=uuidutils.generate_uuid(),
                                tenant_id=tenant_id,
                                name=r['name'],
                                admin_state_up=r['admin_state_up'],
                                status="ACTIVE")
            context.session.add(router_obj)
            if gw_info is not None:
                self._update_router_gw_info(context, router_obj, gw_info)
        return self._make_router_dict(router_obj)

    def update_router(self, context, id, router):
        r = router['router']
        gw_info = r.pop('external_gateway_info', None)
        with context.session.begin(subtransactions=True):
            router_obj = self._get_router(context, id)
            if gw_info is not None:
                self._update_router_gw_info(context, router_obj, gw_info)
            # Ensure we actually have something to update
            if r.keys():
                router_obj.update(r)
            routers = self.get_sync_data(context.elevated(),
                                         [router_obj.id])
            l3_rpc_agent_api.L3AgentNotify.routers_updated(context, routers)
            return self._make_router_dict(router_obj)

    def _update_router_gw_info(self, context, router_obj, info):
        # TODO(salvatore-orlando): guarantee atomic behavior also across
        # operations that span beyond the model classes handled by this
        # class (e.g.: delete_port)
        gw_port = router_obj.gw_port

        network_id = info.get('network_id', None) if info else None
        if network_id:
            # XXX what's the purpose of this
            self._get_network(context, network_id)
            if not self._network_is_external(context, network_id):
                msg = _("Network %s is not a valid external "
                        "network") % network_id
                raise q_exc.BadRequest(resource='router', msg=msg)

        # figure out if we need to delete existing port
        if gw_port and gw_port['network_id'] != network_id:
            fip_count = self.get_floatingips_count(
                context.elevated(),
                {'router_id': [router_obj.id]}
            )
            if fip_count:
                raise l3.RouterExternalGatewayInUseByFloatingIp(
                    router_id=router_obj.id, net_id=gw_port['network_id'])
            with context.session.begin(subtransactions=True):
                router_obj.gw_port = None
                context.session.add(router_obj)

                context.session.expire(gw_port)
                self.delete_port(context.elevated(), gw_port['id'],
                                 l3_port_check=False)
            gw_port = None

        if network_id is not None and (gw_port is None or
                                       gw_port['network_id'] != network_id):
            subnets = self._get_subnets_by_network(context,
                                                   network_id)
            for subnet in subnets:
                self._check_for_dup_router_subnet(context, router_obj,
                                                  network_id, subnet)

            # Port has no 'tenant-id', as it is hidden from user
            gw_port = self.create_port(context.elevated(), {
                'port':
                {'tenant_id': '',  # intentionally not set
                 'network_id': network_id,
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                 'device_id': '',
                 'device_owner': DEVICE_OWNER_ROUTER_GW,
                 'admin_state_up': True,
                 'name': ''}})

            if not gw_port['fixed_ips']:
                self.delete_port(context.elevated(), gw_port['id'],
                                 l3_port_check=False)
                msg = (_('No IPs available for external network %s') %
                       network_id)
                raise q_exc.BadRequest(resource='router', msg=msg)

            with context.session.begin(subtransactions=True):
                router_obj.gw_port = self._get_port(context.elevated(),
                                                    gw_port['id'])
                rp = RouterPort(router_id=router_obj.id,
                                port_id=gw_port['id'],
                                port_type=DEVICE_OWNER_ROUTER_GW)
                router_obj.update({'gw_port_id': gw_port['id']})
                context.session.add(router_obj)
                context.session.add(rp)

    def delete_router(self, context, id):
        with context.session.begin(subtransactions=True):
            router = self._get_router(context, id)

            # Ensure that the router is not used
            fips = self.get_floatingips_count(context.elevated(),
                                              filters={'router_id': [id]})
            if fips:
                raise l3.RouterInUse(router_id=id)

            if any(rp.port_type == DEVICE_OWNER_ROUTER_INTF
                   for rp in router.attached_ports.all()):
                raise l3.RouterInUse(router_id=id)

            # delete any gw port
            for rp in router.attached_ports.all():
                self._delete_port(context.elevated(), rp.port['id'])
            context.session.delete(router)
        l3_rpc_agent_api.L3AgentNotify.router_deleted(context, id)

    def get_router(self, context, id, fields=None):
        router = self._get_router(context, id)
        return self._make_router_dict(router, fields, depth=1)

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'router', limit, marker)
        return self._get_collection(context, Router,
                                    self._make_router_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_routers_count(self, context, filters=None):
        return self._get_collection_count(context, Router,
                                          filters=filters)

    def _check_for_dup_router_subnet(self, context, router,
                                     network_id, subnet):
        try:
            # its possible these ports on on the same network, but
            # different subnet
            new_ipnet = netaddr.IPNetwork(subnet['cidr'])
            for p in [rp.port for rp in router.attached_ports.all()]:
                for ip in p['fixed_ips']:
                    if ip['subnet_id'] == subnet['id']:
                        msg = ("Router already has a port on subnet %s"
                               % subnet['id'])
                        raise q_exc.BadRequest(resource='router', msg=msg)
                    sub_id = ip['subnet_id']
                    cidr = self._get_subnet(context.elevated(),
                                            sub_id)['cidr']
                    ipnet = netaddr.IPNetwork(cidr)
                    match1 = netaddr.all_matching_cidrs(new_ipnet, [cidr])
                    match2 = netaddr.all_matching_cidrs(ipnet, [subnet['cidr']])
                    if match1 or match2:
                        msg = (_("Cidr %(subnet_cidr)s of subnet "
                                 "%(subnet_id)s overlaps with cidr %(cidr)s "
                                 "of subnet %(sub_id)s") %
                               {'subnet_id': subnet['id'],
                                'subnet_cidr': subnet['cidr'],
                                'cidr': cidr,
                                'sub_id': sub_id})
                        raise q_exc.BadRequest(resource='router', msg=msg)
        except exc.NoResultFound:
            pass

    def add_router_interface(self, context, router_id, interface_info):
        router = self._get_router(context, router_id)
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise q_exc.BadRequest(resource='router', msg=msg)

        device_owner = interface_info.get('owner', DEVICE_OWNER_ROUTER_INTF)

        if 'port_id' in interface_info:
            if 'subnet_id' in interface_info:
                msg = _("Cannot specify both subnet-id and port-id")
                raise q_exc.BadRequest(resource='router', msg=msg)

            port = self._get_port(context, interface_info['port_id'])
            if port['device_id'] or port['routerport']:
                raise q_exc.PortInUse(net_id=port['network_id'],
                                      port_id=port['id'],
                                      device_id=port['device_id'])

            fixed_ips = [ip for ip in port['fixed_ips']]
            subnet = self._get_subnet(context, fixed_ips[0]['subnet_id'])
            self._check_for_dup_router_subnet(context, router,
                                              port['network_id'],
                                              subnet)
            with context.session.begin(subtransactions=True):
                port.update({'device_owner': device_owner})
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._get_subnet(context, subnet_id)

            # Ensure the subnet has a gateway
            if not subnet['gateway_ip']:
                msg = _('Subnet for router interface must have a gateway IP')
                raise q_exc.BadRequest(resource='router', msg=msg)
            self._check_for_dup_router_subnet(context, router,
                                              subnet['network_id'],
                                              subnet)

            fixed_ip = {'ip_address': subnet['gateway_ip'],
                        'subnet_id': subnet['id']}
            port = self.create_port(context, {
                'port':
                {'tenant_id': subnet['tenant_id'],
                 'network_id': subnet['network_id'],
                 'fixed_ips': [fixed_ip],
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'admin_state_up': True,
                 'device_id': '',
                 'device_owner': device_owner,
                 'name': ''}})

        with context.session.begin(subtransactions=True):
            rp = RouterPort(port_id=port['id'], router_id=router['id'],
                            port_type=device_owner)
            context.session.add(rp)
            routers = self.get_sync_data(context.elevated(), [router_id])

        l3_rpc_agent_api.L3AgentNotify.routers_updated(
            context, routers, 'add_router_interface',
            {'network_id': port['network_id'],
             'subnet_id': subnet.id})

        info = {'id': router_id,
                'tenant_id': subnet['tenant_id'],
                'port_id': port['id'],
                'subnet_id': port['fixed_ips'][0]['subnet_id']}

        notifier_api.notify(context,
                            notifier_api.publisher_id('network'),
                            'router.interface.create',
                            notifier_api.CONF.default_notification_level,
                            {'router.interface': info})
        return info

    def _confirm_router_interface_not_in_use(self, context, router_id,
                                             subnet_id):
        subnet_db = self._get_subnet(context, subnet_id)
        subnet_cidr = netaddr.IPNetwork(subnet_db['cidr'])
        fip_qry = context.session.query(FloatingIP)
        for fip_db in fip_qry.filter_by(router_id=router_id):
            if netaddr.IPAddress(fip_db['fixed_ip_address']) in subnet_cidr:
                raise l3.RouterInterfaceInUseByFloatingIP(
                    router_id=router_id, subnet_id=subnet_id)

    def remove_router_interface(self, context, router_id, interface_info):
        router = self._get_router(context, router_id)
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise q_exc.BadRequest(resource='router', msg=msg)
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            owner = interface_info.get('owner', DEVICE_OWNER_ROUTER_INTF)
            rp_qry = context.session.query(RouterPort)
            rp_qry = rp_qry.filter_by(port_id=port_id, router_id=router_id,
                                      port_type=owner)
            try:
                router_port = rp_qry.one()
            except exc.NoResultFound:
                raise l3.RouterInterfaceNotFound(router_id=router_id,
                                                 port_id=port_id)
            port_db = router_port.port
            if 'subnet_id' in interface_info:
                port_subnet_id = port_db['fixed_ips'][0]['subnet_id']
                if port_subnet_id != interface_info['subnet_id']:
                    raise q_exc.SubnetMismatchForPort(
                        port_id=port_id,
                        subnet_id=interface_info['subnet_id'])
            subnet_id = port_db['fixed_ips'][0]['subnet_id']
            self._confirm_router_interface_not_in_use(
                context, router_id, subnet_id)
            _network_id = port_db['network_id']
            self.delete_port(context, port_db['id'], l3_port_check=False)
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            self._confirm_router_interface_not_in_use(context, router_id,
                                                      subnet_id)

            subnet = self._get_subnet(context, subnet_id)

            try:
                for rp in router.attached_ports.all()[:]:
                    if rp.port_type != DEVICE_OWNER_ROUTER_INTF:
                        continue
                    elif subnet.network_id != rp.port.network_id:
                        continue

                    p = rp.port
                    port_id = p['id']
                    _network_id = p['network_id']

                    if rp.port.fixed_ips.count() == 1:
                        context.session.delete(rp)
                        self.delete_port(context, p['id'], l3_port_check=False)

                    else:
                        new_fixed_ips = [
                            {
                                'subnet_id': fip['subnet_id'],
                                'ip_address': fip['ip_address']
                            }
                            for fip in rp.port.fixed_ips
                            if fip['subnet_id'] != subnet_id
                        ]

                        self.update_port(
                            context,
                            rp.port.id,
                            {'port': {'fixed_ips': new_fixed_ips}}
                        )
                    break

                else:
                    raise l3.RouterInterfaceNotFoundForSubnet(
                        router_id=router_id,
                        subnet_id=subnet_id)
            except exc.NoResultFound:
                pass

        routers = self.get_sync_data(context.elevated(), [router_id])
        l3_rpc_agent_api.L3AgentNotify.routers_updated(
            context, routers, 'remove_router_interface',
            {'network_id': _network_id,
             'subnet_id': subnet_id})
        notifier_api.notify(context,
                            notifier_api.publisher_id('network'),
                            'router.interface.delete',
                            notifier_api.CONF.default_notification_level,
                            {'router.interface':
                             {'port_id': port_id,
                              'subnet_id': subnet_id}})

    def _get_floatingip(self, context, id):
        try:
            floatingip = self._get_by_id(context, FloatingIP, id)
        except exc.NoResultFound:
            raise l3.FloatingIPNotFound(floatingip_id=id)
        except exc.MultipleResultsFound:
            LOG.error(_('Multiple floating ips match for %s'), id)
            raise l3.FloatingIPNotFound(floatingip_id=id)
        return floatingip

    def _make_floatingip_dict(self, floatingip, fields=None):
        res = {'id': floatingip['id'],
               'tenant_id': floatingip['tenant_id'],
               'floating_ip_address': floatingip['floating_ip_address'],
               'floating_network_id': floatingip['floating_network_id'],
               'router_id': floatingip['router_id'],
               'port_id': floatingip['fixed_port_id'],
               'fixed_ip_address': floatingip['fixed_ip_address']}
        return self._fields(res, fields)

    def _get_router_for_floatingip(self, context, internal_port,
                                   internal_subnet_id,
                                   external_network_id):
        subnet_db = self._get_subnet(context, internal_subnet_id)
        if not subnet_db['gateway_ip']:
            msg = (_('Cannot add floating IP to port on subnet %s '
                     'which has no gateway_ip') % internal_subnet_id)
            raise q_exc.BadRequest(resource='floatingip', msg=msg)

        qry = context.session.query(RouterPort)
        qry = qry.join(models_v2.Port)
        qry = qry.join(models_v2.IPAllocation)
        qry = qry.filter(
            models_v2.Port.network_id==internal_port['network_id'],
            RouterPort.port_type==DEVICE_OWNER_ROUTER_INTF,
            models_v2.IPAllocation.subnet_id==internal_subnet_id
        )

        routerport = qry.first()
        if routerport and routerport.router.gw_port:
            return routerport.router


        raise l3.ExternalGatewayForFloatingIPNotFound(
            subnet_id=internal_subnet_id,
            external_network_id=external_network_id,
            port_id=internal_port['id'])

    def get_assoc_data(self, context, fip, floating_network_id):
        """When a floating IP is associated with an internal port,
        we need to extract/determine some data associated with the
        internal port, including the internal_ip_address, and router_id.
        We also need to confirm that this internal port is owned by the
        tenant who owns the floating IP.
        """
        internal_port = self._get_port(context, fip['port_id'])
        if not internal_port['tenant_id'] == fip['tenant_id']:
            port_id = fip['port_id']
            if 'id' in fip:
                floatingip_id = fip['id']
                msg = _('Port %(port_id)s is associated with a different '
                        'tenant than Floating IP %(floatingip_id)s and '
                        'therefore cannot be bound.')
            else:
                msg = _('Cannnot create floating IP and bind it to '
                        'Port %(port_id)s, since that port is owned by a '
                        'different tenant.')
            raise q_exc.BadRequest(resource='floatingip', msg=msg % locals())

        internal_subnet_id = None
        if 'fixed_ip_address' in fip and fip['fixed_ip_address']:
            internal_ip_address = fip['fixed_ip_address']
            for ip in internal_port['fixed_ips']:
                if ip['ip_address'] == internal_ip_address:
                    internal_subnet_id = ip['subnet_id']
            if not internal_subnet_id:
                msg = (_('Port %(id)s does not have fixed ip %(address)s') %
                       {'id': internal_port['id'],
                        'address': internal_ip_address})
                raise q_exc.BadRequest(resource='floatingip', msg=msg)
        else:
            ips = [ip['ip_address'] for ip in internal_port['fixed_ips']]
            if not ips:
                msg = (_('Cannot add floating IP to port %s that has'
                         'no fixed IP addresses') % internal_port['id'])
                raise q_exc.BadRequest(resource='floatingip', msg=msg)
            if len(ips) > 1:
                msg = (_('Port %s has multiple fixed IPs.  Must provide'
                         ' a specific IP when assigning a floating IP') %
                       internal_port['id'])
                raise q_exc.BadRequest(resource='floatingip', msg=msg)
            internal_ip_address = internal_port['fixed_ips'][0]['ip_address']
            internal_subnet_id = internal_port['fixed_ips'][0]['subnet_id']

        router = self._get_router_for_floatingip(context,
                                                 internal_port,
                                                 internal_subnet_id,
                                                 floating_network_id)
        # confirm that this router has a floating
        # ip enabled gateway with support for this floating IP network
        if (not router or not router.gw_port or
            router.gw_port.network_id != floating_network_id):
            raise l3.ExternalGatewayForFloatingIPNotFound(
                subnet_id=internal_subnet_id,
                port_id=internal_port['id'])

        return (fip['port_id'], internal_ip_address, router['id'])

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        port_id = internal_ip_address = router_id = None
        if fip.get('fixed_ip_address') and not fip.get('port_id'):
            msg = _("fixed_ip_address cannot be specified without a port_id")
            raise q_exc.BadRequest(resource='floatingip', msg=msg)
        if fip.get('port_id'):
            port_id, internal_ip_address, router_id = self.get_assoc_data(
                context,
                fip,
                floatingip_db['floating_network_id'])
            fip_qry = context.session.query(FloatingIP)
            try:
                fip_qry.filter_by(
                    fixed_port_id=fip['port_id'],
                    floating_network_id=floatingip_db['floating_network_id'],
                    fixed_ip_address=internal_ip_address).one()
                raise l3.FloatingIPPortAlreadyAssociated(
                    port_id=fip['port_id'],
                    fip_id=floatingip_db['id'],
                    floating_ip_address=floatingip_db['floating_ip_address'],
                    fixed_ip=internal_ip_address,
                    net_id=floatingip_db['floating_network_id'])
            except exc.NoResultFound:
                pass
        floatingip_db.update({'fixed_ip_address': internal_ip_address,
                              'fixed_port_id': port_id,
                              'router_id': router_id})

    def create_floatingip(self, context, floatingip):
        fip = floatingip['floatingip']
        tenant_id = self._get_tenant_id_for_create(context, fip)
        fip_id = uuidutils.generate_uuid()

        f_net_id = fip['floating_network_id']
        if not self._network_is_external(context, f_net_id):
            msg = _("Network %s is not a valid external network") % f_net_id
            raise q_exc.BadRequest(resource='floatingip', msg=msg)

        try:
            with context.session.begin(subtransactions=True):
                # This external port is never exposed to the tenant.
                # it is used purely for internal system and admin use when
                # managing floating IPs.
                external_port = self.create_port(context.elevated(), {
                    'port':
                    {'tenant_id': '',  # tenant intentionally not set
                     'network_id': f_net_id,
                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                     'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                     'admin_state_up': True,
                     'device_id': fip_id,
                     'device_owner': DEVICE_OWNER_FLOATINGIP,
                     'name': ''}})
                # Ensure IP addresses are allocated on external port
                if not external_port['fixed_ips']:
                    msg = _("Unable to find any IP address on external "
                            "network")
                    raise q_exc.BadRequest(resource='floatingip', msg=msg)

                floating_fixed_ip = external_port['fixed_ips'][0]
                floating_ip_address = floating_fixed_ip['ip_address']
                floatingip_db = FloatingIP(
                    id=fip_id,
                    tenant_id=tenant_id,
                    floating_network_id=fip['floating_network_id'],
                    floating_ip_address=floating_ip_address,
                    floating_port_id=external_port['id'])
                fip['tenant_id'] = tenant_id
                # Update association with internal port
                # and define external IP address
                self._update_fip_assoc(context, fip,
                                       floatingip_db, external_port)
                context.session.add(floatingip_db)
        # TODO(salvatore-orlando): Avoid broad catch
        # Maybe by introducing base class for L3 exceptions
        except q_exc.BadRequest:
            LOG.exception(_("Unable to create Floating ip due to a "
                            "malformed request"))
            raise
        except Exception:
            LOG.exception(_("Floating IP association failed"))
            raise
        router_id = floatingip_db['router_id']
        if router_id:
            routers = self.get_sync_data(context.elevated(), [router_id])
            l3_rpc_agent_api.L3AgentNotify.routers_updated(context, routers,
                                                           'create_floatingip')
        return self._make_floatingip_dict(floatingip_db)

    def update_floatingip(self, context, id, floatingip):
        fip = floatingip['floatingip']
        with context.session.begin(subtransactions=True):
            floatingip_db = self._get_floatingip(context, id)
            fip['tenant_id'] = floatingip_db['tenant_id']
            fip['id'] = id
            fip_port_id = floatingip_db['floating_port_id']
            before_router_id = floatingip_db['router_id']
            self._update_fip_assoc(context, fip, floatingip_db,
                                   self.get_port(context.elevated(),
                                                 fip_port_id))
        router_ids = []
        if before_router_id:
            router_ids.append(before_router_id)
        router_id = floatingip_db['router_id']
        if router_id and router_id != before_router_id:
            router_ids.append(router_id)
        if router_ids:
            routers = self.get_sync_data(context.elevated(), router_ids)
            l3_rpc_agent_api.L3AgentNotify.routers_updated(context, routers,
                                                           'update_floatingip')
        return self._make_floatingip_dict(floatingip_db)

    def delete_floatingip(self, context, id):
        floatingip = self._get_floatingip(context, id)
        router_id = floatingip['router_id']
        with context.session.begin(subtransactions=True):
            context.session.delete(floatingip)
            self.delete_port(context.elevated(),
                             floatingip['floating_port_id'],
                             l3_port_check=False)
        if router_id:
            routers = self.get_sync_data(context.elevated(), [router_id])
            l3_rpc_agent_api.L3AgentNotify.routers_updated(context, routers,
                                                           'delete_floatingip')

    def get_floatingip(self, context, id, fields=None):
        floatingip = self._get_floatingip(context, id)
        return self._make_floatingip_dict(floatingip, fields)

    def get_floatingips(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'floatingip', limit,
                                          marker)
        if filters is not None:
            for key, val in API_TO_DB_COLUMN_MAP.iteritems():
                if key in filters:
                    filters[val] = filters.pop(key)

        return self._get_collection(context, FloatingIP,
                                    self._make_floatingip_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_floatingips_count(self, context, filters=None):
        return self._get_collection_count(context, FloatingIP,
                                          filters=filters)

    def prevent_l3_port_deletion(self, context, port_id):
        """ Checks to make sure a port is allowed to be deleted, raising
        an exception if this is not the case.  This should be called by
        any plugin when the API requests the deletion of a port, since
        some ports for L3 are not intended to be deleted directly via a
        DELETE to /ports, but rather via other API calls that perform the
        proper deletion checks.
        """
        port_db = self._get_port(context, port_id)
        if port_db['device_owner'] in [DEVICE_OWNER_ROUTER_INTF,
                                       DEVICE_OWNER_ROUTER_GW,
                                       DEVICE_OWNER_FLOATINGIP]:
            # Raise port in use only if the port has IP addresses
            # Otherwise it's a stale port that can be removed
            fixed_ips = port_db['fixed_ips'].all()
            if fixed_ips:
                raise l3.L3PortInUse(port_id=port_id,
                                     device_owner=port_db['device_owner'])
            else:
                LOG.debug(_("Port %(port_id)s has owner %(port_owner)s, but "
                            "no IP address, so it can be deleted"),
                          {'port_id': port_db['id'],
                           'port_owner': port_db['device_owner']})

    def disassociate_floatingips(self, context, port_id):
        with context.session.begin(subtransactions=True):
            try:
                fip_qry = context.session.query(FloatingIP)
                floating_ip = fip_qry.filter_by(fixed_port_id=port_id).one()
                router_id = floating_ip['router_id']
                floating_ip.update({'fixed_port_id': None,
                                    'fixed_ip_address': None,
                                    'router_id': None})
            except exc.NoResultFound:
                return
            except exc.MultipleResultsFound:
                # should never happen
                raise Exception(_('Multiple floating IPs found for port %s')
                                % port_id)
        if router_id:
            routers = self.get_sync_data(context.elevated(), [router_id])
            l3_rpc_agent_api.L3AgentNotify.routers_updated(context, routers)

    def _check_l3_view_auth(self, context, network):
        return policy.check(context,
                            "extension:router:view",
                            network)

    def _enforce_l3_set_auth(self, context, network):
        return policy.enforce(context,
                              "extension:router:set",
                              network)

    def _network_is_external(self, context, net_id):
        try:
            context.session.query(ExternalNetwork).filter_by(
                network_id=net_id).one()
            return True
        except exc.NoResultFound:
            return False

    def _extend_network_dict_l3(self, context, network):
        if self._check_l3_view_auth(context, network):
            network[l3.EXTERNAL] = self._network_is_external(
                context, network['id'])

    def _process_l3_create(self, context, net_data, net_id):
        external = net_data.get(l3.EXTERNAL)
        external_set = attributes.is_attr_set(external)

        if not external_set:
            return

        self._enforce_l3_set_auth(context, net_data)

        if external:
            # expects to be called within a plugin's session
            context.session.add(ExternalNetwork(network_id=net_id))

    def _process_l3_update(self, context, net_data, net_id):

        new_value = net_data.get(l3.EXTERNAL)
        if not attributes.is_attr_set(new_value):
            return

        self._enforce_l3_set_auth(context, net_data)
        existing_value = self._network_is_external(context, net_id)

        if existing_value == new_value:
            return

        if new_value:
            context.session.add(ExternalNetwork(network_id=net_id))
        else:
            # must make sure we do not have any external gateway ports
            # (and thus, possible floating IPs) on this network before
            # allow it to be update to external=False
            port = context.session.query(models_v2.Port).filter_by(
                device_owner=DEVICE_OWNER_ROUTER_GW,
                network_id=net_id).first()
            if port:
                raise l3.ExternalNetworkInUse(net_id=net_id)

            context.session.query(ExternalNetwork).filter_by(
                network_id=net_id).delete()

    def _filter_nets_l3(self, context, nets, filters):
        vals = filters and filters.get('router:external', [])
        if not vals:
            return nets

        ext_nets = set([en['network_id'] for en in
                        context.session.query(ExternalNetwork).all()])
        if vals[0]:
            return [n for n in nets if n['id'] in ext_nets]
        else:
            return [n for n in nets if n['id'] not in ext_nets]

    def get_sync_data(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces."""
        with context.session.begin(subtransactions=True):
            router_query = context.session.query(Router)
            if router_ids:
                router_query = router_query.filter(Router.id.in_(router_ids))
            if active:
                router_query = router_query.filter_by(admin_state_up=True)

            return [
                self._make_router_dict(router, depth=2)
                for router in router_query.all()
            ]

    def get_external_network_id(self, context):
        nets = self.get_networks(context, {'router:external': [True]})
        if len(nets) > 1:
            raise q_exc.TooManyExternalNetworks()
        else:
            return nets[0]['id'] if nets else None
