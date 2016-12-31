# Volatility
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.registry as registry
import volatility.plugins.linux.common as common

profiles = [
["LinuxUbuntu_14_04_krn_4_2_AMDx64", 0, 0, 0],
]

class catfishScan(scan.BaseScanner):
    checks = []

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles}) ]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

# based on kdbgscan
class linux_get_profile(common.AbstractLinuxCommand):
    """Automatically detect Mac profiles"""

    @staticmethod
    def check_address(ver_addr, aspace):
        if ver_addr > 0xffffffff:
            ver_addr = ver_addr - 0xffffff8000000000
        elif ver_addr > 0xc0000000:
            ver_addr = ver_addr - 0xc0000000

        ver_buf = aspace.read(ver_addr, 32)
        sig = "Darwin Kernel"
        return ver_buf and ver_buf.startswith(sig)

    @staticmethod
    def guess_profile(aspace):
        """Main interface to guessing Mac profiles. 
        
        Args: 
            aspace: a physical address space.
            
        Returns:
            Tuple containing the profile name and 
            shift address. 
            
            On failure, it implicitly returns None.
        """
        for data in profiles:
            #if linux_get_profile.check_address(data[1], aspace):
            if 1:
                return data[0], 0 
            
        debug.error("Unable to find an appropriate Linux profile for the given memory sample.")

    def calculate(self):
        aspace = utils.load_as(self._config, astype = 'physical')
        
        result = linux_get_profile.guess_profile(aspace)

        if result:
            yield result
        else:
            debug.error("Unable to find an appropriate Linux profile for the given memory sample.")

                    
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Profile", "50"), ("Shift Address", "[addrpad]")])

        for profile, shift_address in data:
            self.table_row(outfd, profile, shift_address)
