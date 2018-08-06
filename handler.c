#include <rain_common.h>

const uint8_t tmp_data[] = {
 0x66,0x48,0x75,0x09,0x64,0xe5,0x99,0xf9,
 0xe9,0x56,0x08,0x06,0x00,0x01,0x08,0x00,
 0x06,0x04,0x00,0x01,0x64,0xe5,0x99,0xf9,
 0xe9,0x56,0xc0,0xa8,0x0a,0xc5,0x00,0x00,
 0x00,0x00,0x00,0x00,0xc0,0xa8
};

#if 0
bool local_ip(in_addr_t network, in_addr_t local_ip,in_addr_t local_netmask)
{
	if (((network ^ local_ip) & local_netmask) == 0){
		return true;
	}
	return false;
}

bool ip_check(struct epoll_ptr_data *epd,char *data,int len){

	struct main_data *md = NULL;
	md = (struct main_data *)epd->gl_var;

	struct options *opt = NULL;
	opt = (struct options *)md->opt;

	int dev = dev_type_enum (opt->dev, opt->dev_type);
	int i=0;

	struct list_data*now = NULL;
	struct ip_info *ii = NULL;
	bool ret = false;

	if(len){}

	if(dev == DEV_TYPE_TUN){
		struct iphdr *iph = (struct iphdr*)(data + 4);

		for(i=0,now = md->ip_li->next; now; now=now->next,i++){
			if(now == NULL){
				break;
			}
			ii = (struct ip_info *)now->data;
			if (((iph->daddr ^ ii->ipaddr) & ii->netmask) == 0){
				ret = true;
				break;
			}
		}
	}else{
		ret = true;
	}

	return ret;
}
#endif


int pipe_rev(int sock ,char *req,int size)
{
	int bytesrecv=0,totalbytesrecvd=0;
	int tsize=0;
	tsize = size;

	while(1){
		bytesrecv=0;
		if(sock != 0){
			bytesrecv=read(sock,req+totalbytesrecvd,tsize);
		}else{
			MM("##ERR: %s %d FD: %d %d ##########\n",__func__,__LINE__,sock,bytesrecv);
			totalbytesrecvd=-1;
			break;
		}
		if(bytesrecv <= 0){
			MM("##ERR: %s %d FD: %d %d ##########\n",__func__,__LINE__,sock,bytesrecv);
			totalbytesrecvd = -1;
			break;
		}else{
			tsize -= bytesrecv;
			totalbytesrecvd += bytesrecv;

			if(totalbytesrecvd == size){
				break;
			}
			continue;
		}
		MM("################# %s %s[:%d] ###\n",__FILE__,__func__,__LINE__);
	}
	return totalbytesrecvd;
}


int pipe_send(int sock,char *data,int size)
{
	int byte=0,total=0;
	int tsize=0;
	int ret = 0;
	tsize = size;
	while(1){
		byte=0;

		if(sock != 0){
			byte=write(sock,data+total,tsize);
		}else{
			MM("##ERR: %s %d FD : %d %d  ###\n",__func__,__LINE__,sock,byte);
			tsize = -1;
			break;
		}
		if(byte < 0){
			MM("##ERR: %s %d FD: %d %d ##########\n",__func__,__LINE__,sock,byte);
			tsize = -1;
			break;
		}
		tsize -= byte;
		total += byte;
		if(total == size){
			break;
		}
		MM("################# %s %s[:%d] ###\n",__FILE__,__func__,__LINE__);
	}
	ret = tsize;
	return ret;
}



int tcp_rev(int sock ,char *req,int size)
{
	int bytesrecv=0,totalbytesrecvd=0;
	int tsize=0;
	tsize = size;
	while(1){
		bytesrecv=0;
		if(sock != 0){
			bytesrecv=read(sock,req+totalbytesrecvd,tsize);
		}else{
			MM("##ERR: %s %d FD: %d %d ##########\n",__func__,__LINE__,sock,bytesrecv);
			totalbytesrecvd=-1;
			break;
		}
		if(bytesrecv == 0){
			//MM("##ERR: %s %d FD: %d %d %d ##########\n",__func__,__LINE__,sock,bytesrecv,size);
			totalbytesrecvd = 0;
			break;

		}else if(bytesrecv < 0){
			MM("##ERR: %s %d FD: %d %d ##########\n",__func__,__LINE__,sock,bytesrecv);
			totalbytesrecvd = 0;
			break;
		}else{
			tsize -= bytesrecv;
			totalbytesrecvd += bytesrecv;

			if(totalbytesrecvd == size){
				break;
			}
			continue;

		}
		MM("################ %s %d %d %d ####\n",__func__,__LINE__,size,totalbytesrecvd);
	}
	return totalbytesrecvd;
}

int tcp_send(int sock,char *data,int size)
{
	int byte=0,total=0;
	int tsize=0;
	int ret = 0;
	tsize = size;

//	if(data[0] == 0 && data[1] == 0){
#if 0
		printf("## S %s %s[:%d] ##\n",__FILE__,__func__,__LINE__);
		dump_print_hex(data,size);
		printf("## E %s %s %d ##\n",__FILE__,__func__,__LINE__);
#endif
//	}

	if(size == 0){
		MM("##ERR: %s %d FD : %d %d %d  ###\n",__func__,__LINE__,sock,byte,size);
		return ret;
	}
	while(1){
		byte=0;
		if(sock != 0){
			byte=write(sock,data+total,tsize);
		}else{
			MM("##ERR: %s %d FD : %d %d  ###\n",__func__,__LINE__,sock,byte);
			tsize = -1;
			break;
		}
		if(byte < 0){
			//MM("##ERR: %s %d FD: %d %d ##########\n",__func__,__LINE__,sock,byte);
			tsize = -1;
			break;
		}else{
			tsize -= byte;
			total += byte;
			if(total == size){
				break;
			}
			continue;

		}
	}
	ret = tsize;
	return ret;
}

int tun_rev(int sock ,char *req,int size)
{
	int bytesrecv=0,totalbytesrecvd=0;
	int i=0;
	while(1){
		bytesrecv=0;
		bytesrecv=read(sock,req+totalbytesrecvd,size);
		if(bytesrecv <= 0){
			MM("##ERR: %s %d FD: %d %d ##########\n",__func__,__LINE__,sock,bytesrecv);
			bytesrecv=0;
			break;
		}else if(bytesrecv > 0){
			break;
		}
		continue;
		i++;
	}
	return bytesrecv;
}

int tun_send(int sock,char *data,int size)
{
	int byte=0,total=0;
	int tsize=0;
	int ret = 0;
	tsize = size;

	while(1){
		byte=0;
		byte=write(sock,data+total,tsize);
		if(byte < 0){
			tsize = -1;
			MM("##ERR: %s %d FD: %d %d ##########\n",__func__,__LINE__,sock,byte);
			break;
		}
		tsize -= byte;
		total += byte;
		if(total == size){
			break;
		}
		continue;
	}
	ret = tsize;

	return ret;
}
