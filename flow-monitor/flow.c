#include "enn-flow-monitor.h"

int flow_db_init(void){
	flow_db_head = NULL;
	return 0;
}


int flow_measure_and_update_db(struct flow_key *fk, int len, struct timeval ts) {
	struct flow_db_entry *p;
	int found = 0;

	/* search flow key in DB */
	p = flow_db_head;
	while(p) {
		if (!memcmp(p->fk, fk, sizeof(struct flow_key))) {
			found = 1;
			break;
		}
		p = p->next;
	}

	/* allocate flow entry data structure */
	if (!found){ 
		p = malloc(sizeof(struct flow_db_entry));
		memset(p, 0, sizeof(struct flow_db_entry));
		if (!p) {
			if (debug) printf("memory allocation error\n");
			return -1;
		}
		p->fk = fk; 

		/* insert in list */
		p->next = flow_db_head;
		flow_db_head = p;
	}

	/* store statistics */
	if (!found)
		p->first_ts = ts;
	p->last_ts = ts;
	p->tot_pck_num += 1;
        p->tot_pck_size += (long)len;	

	return 0;
} 

void flow_db_dump(void) {
	struct flow_db_entry *p = flow_db_head;
	int idx=0;
	float duration; 
	while(p) {
		duration = (float)((p->last_ts.tv_sec*1000000 + p->last_ts.tv_usec) - 
				(p->first_ts.tv_sec*1000000 + p->first_ts.tv_usec)) / 1000000.0f,

		printf("flow id %d\n \
			\tflow %u.%u.%u.%u, %u.%u.%u.%u, %d, %d, %d\n \
			\tnumber of packets %ld\n, \
			\tflow duration %f [s]\n, \
			\ttotal bytes %ld\n",
			idx,
			((uint8_t *)(&p->fk->ipsrc))[0],
			((uint8_t *)(&p->fk->ipsrc))[1],
			((uint8_t *)(&p->fk->ipsrc))[2],
			((uint8_t *)(&p->fk->ipsrc))[3],
			((uint8_t *)(&p->fk->ipdst))[0],
			((uint8_t *)(&p->fk->ipdst))[1],
			((uint8_t *)(&p->fk->ipdst))[2],
			((uint8_t *)(&p->fk->ipdst))[3],
			ntohs(p->fk->srcport), 
			ntohs(p->fk->dstport), 
			p->fk->ipproto, 
			p->tot_pck_num, 
			duration,
			p->tot_pck_size);

	p=p->next;	
		idx++;
	}
}
