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

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants as l3_constants
from neutron.common import exceptions as q_exc
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import l3
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common.notifier import api as notifier_api
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants

LOG = logging.getLogger(__name__)


DEVICE_OWNER_ROUTER_INTF = l3_constants.DEVICE_OWNER_ROUTER_INTF
DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_FLOATINGIP = l3_constants.DEVICE_OWNER_FLOATINGIP
EXTERNAL_GW_INFO = l3.EXTERNAL_GW_INFO

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
    """Represents a v2 neutron router."""

    name = sa.Column(sa.String(255))
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    gw_port_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ports.id', ondelete='CASCADE'))
    gw_port = orm.relationship(models_v2.Port, lazy='joined')
    attached_ports = orm.relationship(
        RouterPort,
        backref='router', lazy='dynamic')


class FloatingIP(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a floating IP address.

    This IP address may or may not be allocated to a tenant, and may or
    may not be associated with an internal port/ip address/router.
    """

    floating_ip_address = sa.Column(sa.String(64), nullable=False)
    floating_network_id = sa.Column(sa.String(36), nullable=False)
    floating_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'),
                                 nullable=False)
    fixed_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    fixed_ip_address = sa.Column(sa.String(64))
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'))
    router = orm.relationship(Router, backref='floating_ips')


class L3_NAT_db_mixin(l3.RouterPluginBase):
    """Mixin class to add L3/NAT router methods to db_plugin_base_v2."""

    l3_rpc_notifier = l3_rpc_agent_api.L3AgentNotify

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_router(self, context, id):
        try:
            router = self._get_by_id(context, Router, id)
        except exc.NoResultFound:
            raise l3.RouterNotFound(router_id=id)
        return router

    def _make_router_dict(self, router, fields=None, process_extensions=True,
                          depth=0):
        res = {'id': router['id'],
               'name': router['name'],
               'tenant_id': router['tenant_id'],
               'admin_state_up': router['admin_state_up'],
               'status': router['status'],
               EXTERNAL_GW_INFO: None,
               'gw_port_id': router['gw_port_id']}

        if router['gw_port_id']:
            nw_id = router.gw_port['network_id']
            res[EXTERNAL_GW_INFO] = {'network_id': nw_id}
        # NOTE(salv-orlando): The following assumes this mixin is used in a
        # class inheriting from CommonDbMixin, which is true for all existing
        # plugins.
        if process_extensions:
            self._apply_dict_extend_functions(
                l3.ROUTERS, res, router)

        if depth:
            if router.gw_port:
                res['gw_port'] = self._core_plugin._make_port_dict(
                    router.gw_port,
                    depth=(depth - 1))
            else:
                res['gw_port'] = None

            # include all ports associated with router as this change allows
            # for custom plugin port types
            res['ports'] = [
                self._core_plugin._make_port_dict(rp.port, depth=(depth - 1))
                for rp in router['attached_ports']
            ]

            # compat for grizzly style
            res[l3_constants.INTERFACE_KEY] = [
                p for p in res['ports']
                if p['device_owner'] == DEVICE_OWNER_ROUTER_INTF
            ]

            res[l3_constants.FLOATINGIP_KEY] = [
                self._make_floatingip_dict(floatingip)
                for floatingip in router.floating_ips
            ]

        return self._fields(res, fields)

    def create_router(self, context, router):
        r = router['router']
        gw_info = r.pop(EXTERNAL_GW_INFO, None)
        tenant_id = self._get_tenant_id_for_create(context, r)

        with context.session.begin(subtransactions=True):
            # pre-generate id so it will be available when
            # configuring external gw port
            router_db = Router(id=uuidutils.generate_uuid(),
                               tenant_id=tenant_id,
                               name=r['name'],
                               admin_state_up=r['admin_state_up'],
                               status="ACTIVE")
            context.session.add(router_db)
            if gw_info:
                self._update_router_gw_info(context, router_db, gw_info)
        return self._make_router_dict(
            router_db,
            process_extensions=False,
            depth=1
        )

    def update_router(self, context, id, router):
        r = router['router']
        gw_info = r.pop(EXTERNAL_GW_INFO, None)
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, id)
            if gw_info is not None:
                self._update_router_gw_info(context, router_db, gw_info)
            # Ensure we actually have something to update
            if r.keys():
                router_db.update(r)
        self.l3_rpc_notifier.routers_updated(
            context, [router_db['id']])
        return self._make_router_dict(router_db, depth=1)

    def _create_router_gw_port(self, context, router, network_id):
        # Port has no 'tenant-id', as it is hidden from user
        gw_port = self._core_plugin.create_port(context.elevated(), {
            'port': {'tenant_id': '',  # intentionally not set
                     'network_id': network_id,
                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                     'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                     'device_id': '',  # formerly router['id'],
                     'device_owner': DEVICE_OWNER_ROUTER_GW,
                     'admin_state_up': True,
                     'name': ''}})

        if not gw_port['fixed_ips']:
            self._core_plugin.delete_port(context.elevated(), gw_port['id'],
                                          l3_port_check=False)
            msg = (_('No IPs available for external network %s') %
                   network_id)
            raise q_exc.BadRequest(resource='router', msg=msg)

        with context.session.begin(subtransactions=True):
            router.gw_port = self._core_plugin._get_port(context.elevated(),
                                                         gw_port['id'])
            rp = RouterPort(router_id=router.id,
                            port_id=gw_port['id'],
                            port_type=DEVICE_OWNER_ROUTER_GW)
            router.gw_port_id = gw_port['id']
            context.session.add(router)
            context.session.add(rp)

    def _update_router_gw_info(self, context, router, info):
        # TODO(salvatore-orlando): guarantee atomic behavior also across
        # operations that span beyond the model classes handled by this
        # class (e.g.: delete_port)
        gw_port = router.gw_port
        # network_id attribute is required by API, so it must be present
        network_id = info.get('network_id') if info else None
        if network_id:
            network_db = self._core_plugin._get_network(context, network_id)
            if not network_db.external:
                msg = _("Network %s is not a valid external "
                        "network") % network_id
                raise q_exc.BadRequest(resource='router', msg=msg)

        # figure out if we need to delete existing port
        if gw_port and gw_port['network_id'] != network_id:
            fip_count = self.get_floatingips_count(
                context.elevated(),
                {'router_id': [router.id]}
            )
            if fip_count:
                raise l3.RouterExternalGatewayInUseByFloatingIp(
                    router_id=router.id, net_id=gw_port['network_id'])
            with context.session.begin(subtransactions=True):
                router.gw_port = None
                context.session.add(router)
                context.session.expire(gw_port)
            self._core_plugin.delete_port(context.elevated(), gw_port['id'],
                                          l3_port_check=False)
            gw_port = None

        if network_id is not None and (gw_port is None or
                                       gw_port['network_id'] != network_id):
            subnets = self._core_plugin._get_subnets_by_network(context,
                                                                network_id)
            for subnet in subnets:
                self._check_for_dup_router_subnet(context, router,
                                                  network_id, subnet)
            self._create_router_gw_port(context, router, network_id)

    def delete_router(self, context, id):
        with context.session.begin(subtransactions=True):
            router = self._get_router(context, id)

            # Ensure that the router is not used
            fips = self.get_floatingips_count(context.elevated(),
                                              filters={'router_id': [id]})
            if fips:
                raise l3.RouterInUse(router_id=id)

            if router.attached_ports.filter_by(
                    port_type=DEVICE_OWNER_ROUTER_INTF).count():
            #TODO(mark)
            #if any(rp.port_type == DEVICE_OWNER_ROUTER_INTF
            #       for rp in router.attached_ports.all()):
                raise l3.RouterInUse(router_id=id)

            #TODO(nati) Refactor here when we have router insertion model
            vpnservice = manager.NeutronManager.get_service_plugins().get(
                constants.VPN)
            if vpnservice:
                vpnservice.check_router_in_use(context, id)

            router.gw_port = None  # Do we need this?  This doesn't appear
                                   # upstream
            for rp in router.attached_ports.all():
                self._core_plugin._delete_port(
                    context.elevated(),
                    rp.port['id'],
                    l3_port_check=False
                )
            context.session.delete(router)
        self.l3_rpc_notifier.router_deleted(context, id)

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
            new_ipnet = netaddr.IPNetwork(subnet['cidr'])
            for p in [rp.port for rp in router.attached_ports]:
                for ip in p['fixed_ips']:
                    if ip['subnet_id'] == subnet['id']:
                        msg = (_("Router already has a port on subnet %s") %
                               subnet['id'])
                        raise q_exc.BadRequest(resource='router', msg=msg)
                    sub_id = ip['subnet_id']
                    cidr = self._core_plugin._get_subnet(context.elevated(),
                                                         sub_id)['cidr']
                    ipnet = netaddr.IPNetwork(cidr)
                    match1 = netaddr.all_matching_cidrs(new_ipnet, [cidr])
                    match2 = netaddr.all_matching_cidrs(
                        ipnet,
                        [subnet['cidr']]
                    )
                    if match1 or match2:
                        data = {'subnet_cidr': subnet.cidr,
                                'subnet_id': subnet.id,
                                'cidr': cidr,
                                'sub_id': sub_id}
                        msg = (_("Cidr %(subnet_cidr)s of subnet "
                                 "%(subnet_id)s overlaps with cidr %(cidr)s "
                                 "of subnet %(sub_id)s") % data)
                        raise q_exc.BadRequest(resource='router', msg=msg)
        except exc.NoResultFound:
            pass

    def add_router_interface(self, context, router_id, interface_info):
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise q_exc.BadRequest(resource='router', msg=msg)

        # make sure router exists
        new_to_router = True
        router = self._get_router(context, router_id)
        device_owner = interface_info.get('owner', DEVICE_OWNER_ROUTER_INTF)

        if 'port_id' in interface_info:
            # make sure port update is committed
            with context.session.begin(subtransactions=True):
                if 'subnet_id' in interface_info:
                    msg = _("Cannot specify both subnet-id and port-id")
                    raise q_exc.BadRequest(resource='router', msg=msg)

                port = self._core_plugin._get_port(context,
                                                   interface_info['port_id'])
                if port['device_id'] or port['routerport']:
                    raise q_exc.PortInUse(net_id=port['network_id'],
                                          port_id=port['id'],
                                          device_id=port['device_id'])
                fixed_ips = [ip for ip in port['fixed_ips']]
                subnet = self._core_plugin._get_subnet(
                    context, fixed_ips[0]['subnet_id'])
                self._check_for_dup_router_subnet(context, router,
                                                  port['network_id'],
                                                  subnet)
                port['device_owner'] = device_owner
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._core_plugin._get_subnet(context, subnet_id)
            # Ensure the subnet has a gateway
            if not subnet['gateway_ip']:
                msg = _('Subnet for router interface must have a gateway IP')
                raise q_exc.BadRequest(resource='router', msg=msg)
            self._check_for_dup_router_subnet(context, router,
                                              subnet['network_id'],
                                              subnet)
            fixed_ip = {'ip_address': subnet['gateway_ip'],
                        'subnet_id': subnet['id']}
            # check if network is already attached to the router
            for rp in router.attached_ports:
                if rp.port.network_id == subnet.network_id:
                    fixed_ips = [
                        {
                            'subnet_id': ip['subnet_id'],
                            'ip_address': ip['ip_address']
                        }
                        for ip in rp.port["fixed_ips"]
                    ]
                    fixed_ips.append(fixed_ip)
                    port = self._core_plugin.update_port(
                        context,
                        rp.port_id,
                        {'port': {'fixed_ips': fixed_ips}}
                    )
                    new_to_router = False
                    break
            else:
                port = self._core_plugin.create_port(context, {
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
            if new_to_router:
                rp = RouterPort(
                    port_id=port['id'],
                    router_id=router['id'],
                    port_type=device_owner
                )
                context.session.add(rp)

        self.l3_rpc_notifier.routers_updated(
            context, [router_id], 'add_router_interface')

        info = {
            'id': router_id,
            'tenant_id': subnet['tenant_id'],
            'port_id': port['id'],
            'subnet_id': interface_info.get(
                'subnet_id',
                port['fixed_ips'][0]['subnet_id']
            )
        }

        notifier_api.notify(context,
                            notifier_api.publisher_id('network'),
                            'router.interface.create',
                            notifier_api.CONF.default_notification_level,
                            {'router.interface': info})
        return info

    def _confirm_router_interface_not_in_use(self, context, router_id,
                                             subnet_id):
        subnet_db = self._core_plugin._get_subnet(context, subnet_id)
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
            subnet = self._core_plugin._get_subnet(context, subnet_id)
            self._confirm_router_interface_not_in_use(
                context, router_id, subnet_id)
            self._core_plugin.delete_port(context, port_db['id'],
                                          l3_port_check=False)
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            self._confirm_router_interface_not_in_use(context, router_id,
                                                      subnet_id)

            subnet = self._core_plugin._get_subnet(context, subnet_id)

            for rp in router.attached_ports.all():
                if rp.port_type != DEVICE_OWNER_ROUTER_INTF:
                    continue
                elif subnet.network_id != rp.port.network_id:
                    continue

                port_id = rp.port.id

                if len(set(f['subnet_id'] for f in rp.port.fixed_ips)) == 1:
                    context.session.delete(rp)
                    self._core_plugin.delete_port(
                        context,
                        port_id,
                        l3_port_check=False
                    )

                else:
                    new_fixed_ips = [
                        {
                            'subnet_id': fip['subnet_id'],
                            'ip_address': fip['ip_address']
                        }
                        for fip in rp.port.fixed_ips
                        if fip['subnet_id'] != subnet_id
                    ]

                    self._core_plugin.update_port(
                        context,
                        rp.port.id,
                        {'port': {'fixed_ips': new_fixed_ips}}
                    )
                break

            else:
                raise l3.RouterInterfaceNotFoundForSubnet(
                    router_id=router_id,
                    subnet_id=subnet_id)

        self.l3_rpc_notifier.routers_updated(
            context, [router_id], 'remove_router_interface')
        info = {'id': router_id,
                'tenant_id': subnet['tenant_id'],
                'port_id': port_id,
                'subnet_id': subnet_id}
        notifier_api.notify(context,
                            notifier_api.publisher_id('network'),
                            'router.interface.delete',
                            notifier_api.CONF.default_notification_level,
                            {'router.interface': info})
        return info

    def _get_floatingip(self, context, id):
        try:
            floatingip = self._get_by_id(context, FloatingIP, id)
        except exc.NoResultFound:
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
        subnet_db = self._core_plugin._get_subnet(context,
                                                  internal_subnet_id)
        if not subnet_db['gateway_ip']:
            msg = (_('Cannot add floating IP to port on subnet %s '
                     'which has no gateway_ip') % internal_subnet_id)
            raise q_exc.BadRequest(resource='floatingip', msg=msg)

        qry = context.session.query(RouterPort)
        qry = qry.join(models_v2.Port)
        qry = qry.join(models_v2.IPAllocation)
        qry = qry.filter(
            models_v2.Port.network_id == internal_port['network_id'],
            RouterPort.port_type == DEVICE_OWNER_ROUTER_INTF,
            models_v2.IPAllocation.subnet_id == internal_subnet_id
        )

        routerport = qry.first()
        if routerport and routerport.router.gw_port:
            return routerport.router

        raise l3.ExternalGatewayForFloatingIPNotFound(
            subnet_id=internal_subnet_id,
            external_network_id=external_network_id,
            port_id=internal_port['id'])

    def _internal_fip_assoc_data(self, context, fip):
        """Retrieve internal port data for floating IP.

        Retrieve information concerning the internal port where
        the floating IP should be associated to.
        """
        internal_port = self._core_plugin._get_port(context, fip['port_id'])
        if not internal_port['tenant_id'] == fip['tenant_id']:
            port_id = fip['port_id']
            if 'id' in fip:
                floatingip_id = fip['id']
                data = {'port_id': port_id,
                        'floatingip_id': floatingip_id}
                msg = (_('Port %(port_id)s is associated with a different '
                         'tenant than Floating IP %(floatingip_id)s and '
                         'therefore cannot be bound.') % data)
            else:
                msg = (_('Cannnot create floating IP and bind it to '
                         'Port %s, since that port is owned by a '
                         'different tenant.') % port_id)
            raise q_exc.BadRequest(resource='floatingip', msg=msg)

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
        return internal_port, internal_subnet_id, internal_ip_address

    def get_assoc_data(self, context, fip, floating_network_id):
        """Determine/extract data associated with the internal port.

        When a floating IP is associated with an internal port,
        we need to extract/determine some data associated with the
        internal port, including the internal_ip_address, and router_id.
        We also need to confirm that this internal port is owned by the
        tenant who owns the floating IP.
        """
        (internal_port, internal_subnet_id,
         internal_ip_address) = self._internal_fip_assoc_data(context, fip)
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
                external_network_id=floating_network_id,
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
        if not self._core_plugin._network_is_external(context, f_net_id):
            msg = _("Network %s is not a valid external network") % f_net_id
            raise q_exc.BadRequest(resource='floatingip', msg=msg)

        with context.session.begin(subtransactions=True):
            # This external port is never exposed to the tenant.
            # it is used purely for internal system and admin use when
            # managing floating IPs.
            external_port = self._core_plugin.create_port(context.elevated(), {
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
                raise q_exc.ExternalIpAddressExhausted(net_id=f_net_id)

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

        router_id = floatingip_db['router_id']
        if router_id:
            self.l3_rpc_notifier.routers_updated(
                context, [router_id],
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
                                   self._core_plugin.get_port(
                                       context.elevated(), fip_port_id))
        router_ids = []
        if before_router_id:
            router_ids.append(before_router_id)
        router_id = floatingip_db['router_id']
        if router_id and router_id != before_router_id:
            router_ids.append(router_id)
        if router_ids:
            self.l3_rpc_notifier.routers_updated(
                context, router_ids, 'update_floatingip')
        return self._make_floatingip_dict(floatingip_db)

    def delete_floatingip(self, context, id):
        floatingip = self._get_floatingip(context, id)
        router_id = floatingip['router_id']
        with context.session.begin(subtransactions=True):
            context.session.delete(floatingip)
            self._core_plugin.delete_port(context.elevated(),
                                          floatingip['floating_port_id'],
                                          l3_port_check=False)
        if router_id:
            self.l3_rpc_notifier.routers_updated(
                context, [router_id],
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
        """Checks to make sure a port is allowed to be deleted.

        Raises an exception if this is not the case.  This should be called by
        any plugin when the API requests the deletion of a port, since some
        ports for L3 are not intended to be deleted directly via a DELETE
        to /ports, but rather via other API calls that perform the proper
        deletion checks.
        """
        port_db = self._core_plugin._get_port(context, port_id)
        if port_db['device_owner'] in [DEVICE_OWNER_ROUTER_INTF,
                                       DEVICE_OWNER_ROUTER_GW,
                                       DEVICE_OWNER_FLOATINGIP]:
            # Raise port in use only if the port has IP addresses
            # Otherwise it's a stale port that can be removed
            fixed_ips = port_db['fixed_ips']
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
            self.l3_rpc_notifier.routers_updated(
                context, [router_id])

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
