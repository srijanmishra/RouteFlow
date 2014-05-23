from rflib.components.resources import *

class Algorithms(object):
    def __init__(self):
        self.id_ = 0

    #Checks topoPhysical full connectivity and updates topoVirtual links accordingly to topoPhysical links             
    def map_topos(self, topoPhysical, topoVirtual):
        if ( topoPhysical.check_topo_conection() ):
            topoVirtual_map_data_virtual_planes = topoVirtual.get_map_data_virtual_planes()
            dps_topoPhysical = topoPhysical.get_dps()
            topoVirtual_map_virtual_plane = topoVirtual.get_map_virtual_plane()
            topoPhysical_links = topoPhysical.get_links()
            for link in topoPhysical_links.keys():
                src = link.src
                dst = link.dst
                if (src.id, src.port) in topoVirtual_map_data_virtual_planes.keys() \
                and (dst.id, dst.port) in topoVirtual_map_data_virtual_planes.keys():
                    (src_vmid, src_intf) = topoVirtual_map_data_virtual_planes[(src.id, src.port)]
                    (dst_vmid, dst_intf) = topoVirtual_map_data_virtual_planes[(dst.id, dst.port)]
                    if (src_vmid, src_intf) in topoVirtual_map_virtual_plane.values() and (dst_vmid, dst_intf) in topoVirtual_map_virtual_plane.values():
                        vsid_src,vsid_src_port = topoVirtual_map_virtual_plane.keys()[topoVirtual_map_virtual_plane.values().index( (src_vmid, src_intf) )]
                        vsid_dst,vsid_dst_port = topoVirtual_map_virtual_plane.keys()[topoVirtual_map_virtual_plane.values().index( (dst_vmid, dst_intf) )]
                        if (vsid_src,vsid_src_port) and (vsid_dst,vsid_dst_port):
                            topoVirtual.register_link(src_vmid, src_intf, dst_vmid, dst_intf, vsid_src=vsid_src, vsid_src_port=vsid_src_port, vsid_dst=vsid_dst, vsid_dst_port=vsid_dst_port)
                    else:
                        topoVirtual.register_link(src_vmid, src_intf, dst_vmid, dst_intf, vsid_src=None, vsid_src_port=None, vsid_dst=None, vsid_dst_port=None)
                
            links_topovirt = topoVirtual.get_links()
            num_virt_links = len(links_topovirt)
            log.info("Mapping topos: topo virt links %s", num_virt_links)

            links_topophy = topoPhysical.get_links()
            num_phy_links = len(links_topophy)
            log.info("Mapping topos: topo phy links %s", num_phy_links)        