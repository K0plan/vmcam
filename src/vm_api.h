/**
 * Copyright (c) 2014 Iwan Timmer
 * 
 * This file is part of VMCam.
 * 
 * VMCam is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * VMCam is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with VMCam.  If not, see <http://www.gnu.org/licenses/>.
 */

unsigned int key_interval;

void vm_config(char* vcas_address, unsigned int vcas_port, char* vks_address,
        unsigned int vks_port, char* company, char* dir, char* amino_mac,
        char* machine_id, int protocolVersion);
int init_vmapi();
int load_keyblock(const char *channel_id);
