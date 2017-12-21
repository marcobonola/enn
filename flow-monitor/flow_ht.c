#include "enn-flow-monitor.h"

int flow_db_init(void){
	flow_db = NULL;
	return 0;
}


int flow_measure_and_update_db(struct flow_key *fk, int len, struct timeval ts) {
	struct flow_db_entry *p=NULL;
	int found = 0;

	/* search flow key in DB */
	HASH_FIND(hh, flow_db, fk, sizeof(struct flow_key), p);

	/* allocate flow entry data structure */
	if (!p){ 
		p = malloc(sizeof(struct flow_db_entry));
		memset(p, 0, sizeof(struct flow_db_entry));
		if (!p) {
			if (debug) printf("memory allocation error\n");
			return -1;
		}
		p->fk = fk; 

		/* insert in flow HT */
		HASH_ADD(hh, flow_db, fk, sizeof(struct flow_key), p);
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
	struct flow_db_entry *temp, *p = NULL;
	int idx=0;
	float duration; 
	if (!debug) return;
	HASH_ITER(hh, flow_db, p, temp) {
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

		idx++;
	}
}
