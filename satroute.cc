/*
 * Contributed by Tom Henderson, UCB Daedalus Research Group, June 1999
 * Revised by Xin Xu, Sep 2022.
 */

#include <cmath>
#include <sys/time.h>   
#include <time.h>   
#include "satroute.h"
#include "sattrace.h"
#include "satnode.h"
#include "satlink.h"
#include "route.h"
#include <address.h>
#include "Graph.h"  

int hdr_SatDV::offset_;
time_t lasttime = 0;  
struct timeval lasttv;
struct tm *lastt;

static class SatDVHeaderClass : public PacketHeaderClass {
public:
	SatDVHeaderClass() : PacketHeaderClass("PacketHeader/SatRouteAgent",
                                                sizeof(hdr_SatDV)) {
		bind_offset(&hdr_SatDV::offset_);
	}
} class_SatRoute_hdr;

static class SatRouteClass:public TclClass
{
  public:
	SatRouteClass ():TclClass ("Agent/SatRoute") { }
	TclObject *create (int, const char *const *) {
    		return (new SatRouteAgent ());
	}
} class_satroute;

SatRouteAgent::SatRouteAgent (): Agent (PT_MESSAGE), maxslot_(0), nslot_(0), slot_(0)
{
	bind ("myaddr_", &myaddr_);
}

SatRouteAgent::~SatRouteAgent()
{
	if (slot_)
	    delete [] slot_;
}

void SatRouteAgent::alloc(int slot)
{
	slot_entry *old = slot_;
	int n = nslot_;
	if (old == 0)
		nslot_ = 32;
	while (nslot_ <= slot)
		nslot_ <<= 1;
	slot_ = new slot_entry[nslot_];
	memset(slot_, 0, nslot_ * sizeof(slot_entry));
	for (int i = 0; i < n; ++i) {
		slot_[i].next_hop = old[i].next_hop;
		slot_[i].entry = old[i].entry;
	}
	delete [] old;
}

void SatRouteAgent::install(int slot, int nh, NsObject* p)
{
	if (slot >= nslot_)
		alloc(slot);
	slot_[slot].next_hop = nh;
	slot_[slot].entry = p;
	if (slot >= maxslot_)
		maxslot_ = slot;
}

void SatRouteAgent::clear_slots()
{
	if (slot_)
		delete [] slot_;
	slot_ = 0;
	nslot_ = 0;
	maxslot_ = -1;
}

int SatRouteAgent::command (int argc, const char *const *argv)
{
        Tcl& tcl = Tcl::instance();
        if (argc == 2) {

        }
        if (argc == 3) {
               if (strcmp(argv[1], "set_node") == 0) {
                        node_ = (SatNode *) TclObject::lookup(argv[2]);
                        if (node_ == 0) {
                                tcl.resultf("no such object %s", argv[2]);
                                return (TCL_ERROR);
                        }
                        return (TCL_OK);
		}
	}
	return (Agent::command (argc, argv));
}

/*
 *  Find a target for the received packet
 */
void SatRouteAgent::forwardPacket(Packet * p)
{
	hdr_ip *iph = hdr_ip::access(p);
  	hdr_cmn *hdrc = HDR_CMN (p);
	NsObject *link_entry_;

	hdrc->direction() = hdr_cmn::DOWN; // send it down the stack
	int dst = Address::instance().get_nodeaddr(iph->daddr());
	// Here we need to have an accurate encoding of the next hop routing
	// information
	if (myaddr_ == iph->daddr()) {
		printf("Error:  trying to forward a packet destined to self: %d\n", myaddr_); 
		Packet::free(p);
	}
	hdrc->addr_type_ = NS_AF_INET;
	hdrc->last_hop_ = myaddr_; // for tracing purposes 
	if (SatRouteObject::instance().data_driven_computation())
		SatRouteObject::instance().recompute_node(myaddr_);
	if (SatNode::dist_routing_ == 0) {
		if (slot_ == 0) { // No routes to anywhere
			if (node_->trace())
				node_->trace()->traceonly(p);
			Packet::free(p);
			return;
		}
		link_entry_ = slot_[dst].entry;

		if (link_entry_ == 0) {
			if (node_->trace())
				node_->trace()->traceonly(p);
			Packet::free(p);
			return;
		}
		hdrc->next_hop_ = slot_[dst].next_hop;
		link_entry_->recv(p, (Handler *)0);
		return;
	} else {
		// DISTRIBUTED ROUTING LOOKUP COULD GO HERE
		printf("Error:  distributed routing not available\n");
		exit(1);
	}
}

void SatRouteAgent::recv (Packet * p, Handler *)
{
	hdr_ip *iph = hdr_ip::access(p);
	hdr_cmn *cmh = hdr_cmn::access(p);

	if (iph->saddr() == myaddr_ && cmh->num_forwards() == 0) {
	 	// Must be a packet I'm originating... add the IP header
		iph->ttl_ = IP_DEF_TTL;
	} else if (iph->saddr() == myaddr_) {
		// I received a packet that I sent.  Probably a routing loop.
		Packet::free(p);
		return;
	} else {
		// Packet I'm forwarding...
		// Check the TTL.  If it is zero, then discard.
		if(--iph->ttl_ == 0) {
			Packet::free(p);
			return;
		}
	}
	if ((iph->saddr() != myaddr_) && (iph->dport() == ROUTER_PORT)) {
		// DISTRIBUTED ROUTING PROTOCOL COULD GO HERE
		printf("Error:  distributed routing not available\n");
		exit(1);
	} else {
		forwardPacket(p);
	}
}

static class SatRouteObjectClass:public TclClass
{
  public:
        SatRouteObjectClass ():TclClass ("SatRouteObject") { }
        TclObject *create (int, const char *const *) {
                return (new SatRouteObject ());
        }
} class_satrouteobject;

SatRouteObject* SatRouteObject::instance_;
int SatRouteObject::kspstate[N][N]; 

SatRouteObject::SatRouteObject() : suppress_initial_computation_(0) 
{
    memset((char *)matrix_qlen_, 0, size_ * size_ * sizeof(matrix_qlen_[0]));  
	for(int i=0;i<N;i++)   
		for(int j=0;j<N;j++)
		{
			minlen[i][j] = -2;
			kspstate[i][j] = -1;
			kspnum[i][j] = 0;

			for(int k=0;k<PATHNUM;k++)
			{
        			memset((char *)kspinfo[i][j][k], 0, N);
        			kspflag[i][j][k]=0;
			}
		}

	gettimeofday(&lasttv, NULL);

	bind_bool("wiredRouting_", &wiredRouting_);
	bind_bool("metric_delay_", &metric_delay_);
	bind_bool("data_driven_computation_", &data_driven_computation_);

}

int SatRouteObject::command (int argc, const char *const *argv)
{
        if (instance_ == 0)
                instance_ = this;
	if (argc == 2) {
		// While suppress_initial_computation_ may seem more 
		// appropriate as a bound variable, it is useful to 
		// implement the setting of this variable this way so that 
		// the ``instance_ = this'' assignment is made at the
		// start of simulation.
		if (strcmp(argv[1], "suppress_initial_computation") == 0) {
			suppress_initial_computation_ = 1;
			return (TCL_OK);
		}
		if (strcmp(argv[1], "compute_routes") == 0) {
			recompute();
			return (TCL_OK);
		}
		if (strcmp(argv[1], "dump") == 0) {
			printf("Dumping\n");
			dump();
			return (TCL_OK);
		}
	}

	return (RouteLogic::command(argc, argv));
}                       

// Wrapper to catch whether OTcl-based (wired-satellite) routing is enabled
void SatRouteObject::insert_link(int src, int dst, double cost)
{
	if (wiredRouting_) {
		Tcl::instance().evalf("[Simulator instance] sat_link_up %d %d %f", (src - 1), (dst - 1), cost);
	} else
		insert(src, dst, cost);
}

// Wrapper to catch whether OTcl-based (wired) routing is enabled
void SatRouteObject::insert_link(int src, int dst, double cost, void* entry)
{
	SatLinkHead* slhp = (SatLinkHead*) entry;
	if (wiredRouting_) {
		// Here we do an upcall to an instproc in ns-sat.tcl
		// that populates the link_(:) array
		Tcl::instance().evalf("[Simulator instance] sat_link_up %d %d %f %s %s", (src - 1), (dst - 1), cost, slhp->name(), slhp->queue()->name());
	} else
		insert(src, dst, cost, entry); // base class insert()
}

void SatRouteObject::recompute_node(int node)
{
	compute_topology();
	node_compute_routes(node);
	populate_routing_tables(node);
}
void SatRouteObject::recompute()
{
	// For very large topologies (e.g., Teledesic), we don't want to
	// waste a lot of time computing routes at the beginning of the
	// simulation.  This first if() clause suppresses route computations.
	if (data_driven_computation_ ||
	    (NOW < 0.001 && suppress_initial_computation_) ) 
		return;
	else {
		compute_topology();
		if (wiredRouting_) {
			Tcl::instance().evalf("[Simulator instance] compute-flat-routes");
		} else {
			compute_routes(); // base class function
		}
		populate_routing_tables();
	}
}

// topology information to the RouteLogic.
void SatRouteObject::compute_topology()
{
	Node *nodep;
	Phy *phytxp, *phyrxp, *phytxp2, *phyrxp2;
	SatLinkHead *slhp;
	Channel *channelp, *channelp2;
	Queue *satqueue;   
	int qlen;   
	int src, dst; 
	double delay;
	double tempdelay;   

	// wired-satellite integration
	if (wiredRouting_) {
		// There are two route objects being used
		// a SatRouteObject and a RouteLogic (for wired)
		// We need to also reset the RouteLogic one
		Tcl::instance().evalf("[[Simulator instance] get-routelogic] reset");
	}
	reset_all();
	// Compute adjacencies.  Traverse linked list of nodes 
        for (nodep=Node::nodehead_.lh_first; nodep; nodep = nodep->nextnode()) {
	    // Cycle through the linked list of linkheads
	    if (!SatNode::IsASatNode(nodep->address()))
	        continue;
	    for (slhp = (SatLinkHead*) nodep->linklisthead().lh_first; slhp; 
	      slhp = (SatLinkHead*) slhp->nextlinkhead()) {
		if (slhp->type() == LINK_GSL_REPEATER)
		    continue;
		if (!slhp->linkup_)
		    continue;
		phytxp = (Phy *) slhp->phy_tx();
		assert(phytxp);
		channelp = phytxp->channel();
		if (!channelp) 
	 	    continue; // Not currently connected to channel
		// Next, look for receive interfaces on this channel
		phyrxp = channelp->ifhead_.lh_first;
		for (; phyrxp; phyrxp = phyrxp->nextchnl()) {
		    if (phyrxp == phytxp) {
			printf("Configuration error:  a transmit interface \
			  is a channel target\n");
			exit(1);
		    } 
		    if (phyrxp->head()->type() == LINK_GSL_REPEATER) {
			double delay_firsthop = ((SatChannel*)
				    channelp)->get_pdelay(phytxp->node(), 
				    phyrxp->node());
			if (!((SatLinkHead*)phyrxp->head())->linkup_)
		    	    continue;
			phytxp2 = ((SatLinkHead*)phyrxp->head())->phy_tx();
			channelp2 = phytxp2->channel();
			if (!channelp2) 
	 	    	    continue; // Not currently connected to channel
			phyrxp2 = channelp2->ifhead_.lh_first;
			for (; phyrxp2; phyrxp2 = phyrxp2->nextchnl()) {
		    	    if (phyrxp2 == phytxp2) {
			        printf("Config error: a transmit interface \
			          is a channel target\n");
			        exit(1);
			    }
		            // Found an adjacency relationship.
		            // Add this link to the RouteLogic
		            src = phytxp->node()->address() + 1;
		            dst = phyrxp2->node()->address() + 1;
			    if (src == dst)
				continue;
			    if (metric_delay_)
		                delay = ((SatChannel*) 
			          channelp2)->get_pdelay(phytxp2->node(), 
			          phyrxp2->node());
			    else {
				delay = 1;
				delay_firsthop = 0;
			    }
			    insert_link(src, dst, delay+delay_firsthop, (void*)slhp);
			}
		    } else {
		        // Found an adjacency relationship.
		        // Add this link to the RouteLogic
		        src = phytxp->node()->address() + 1;
		        dst = phyrxp->node()->address() + 1;
			if (metric_delay_)
		            delay = ((SatChannel*) 
		              channelp)->get_pdelay(phytxp->node(), 
			      phyrxp->node());
			else
			    delay = 1;
			insert_link(src, dst, delay, (void*)slhp);  

			satqueue = (Queue *) slhp->queue();
			qlen = satqueue->byteLength(); 
			matrix_qlen_[INDEX(src, dst, size_)].qlen = qlen;     
			}
		}
	    }
	}
}

void SatRouteObject::populate_routing_tables(int node)
{
	SatNode *snodep = (SatNode*) Node::nodehead_.lh_first;
	SatNode *snodep2;
	int next_hop, src, dst;
	NsObject *target;

	if (wiredRouting_) {
		Tcl::instance().evalf("[Simulator instance] populate-flat-classifiers [Node set nn_]");
		return;
	}
        for (; snodep; snodep = (SatNode*) snodep->nextnode()) {
		if (!SatNode::IsASatNode(snodep->address()))
			continue;   
		// First, clear slots of the current routing table
		if (snodep->ragent())
			snodep->ragent()->clear_slots();
		src = snodep->address();
		if (node != -1 && node != src)
			continue;
		snodep2 = (SatNode*) Node::nodehead_.lh_first;
		for (; snodep2; snodep2 = (SatNode*) snodep2->nextnode()) {
                        if (!SatNode::IsASatNode(snodep->address()))
                                continue;
			dst = snodep2->address();
			next_hop = lookup(src, dst);

			if (next_hop != -1 && src != dst) {
				// Here need to insert target into slot table
				target = (NsObject*) lookup_entry(src, dst);
				if (target == 0) {
					printf("Error, routelogic target ");
					printf("not populated %f\n", NOW); 
					exit(1);
				}
				((SatNode*)snodep)->ragent()->install(dst, 
				    next_hop, target); 
			}
		}
	}
}

int SatRouteObject::lookup(int s, int d)
{                                       
	int src = s + 1;        
	int dst = d + 1;
	if (src >= size_ || dst >= size_) {
		return (-1); // Next hop = -1
	}
	return (route_[INDEX(src, dst, size_)].next_hop - 1);
}

void* SatRouteObject::lookup_entry(int s, int d)
{                       
	int src = s + 1;
	int dst = d + 1;
	if (src >= size_ || dst >= size_) {
		return (0); // Null pointer
	}
	return (route_[INDEX(src, dst, size_)].entry);
}

void SatRouteObject::node_compute_routes(int node)
{
    int n = size_;
    int l=0;
    int* parent = new int[n];
    double* hopcnt = new double[n];
	int** ksp = new int*[PATHNUM];
	double min = 0;
	struct timeval tv;  
	struct tm *t;
	double now, last;
	double path1 = 0;    
	double temppath1 = 0;    
	int Qth = 15000;    //Qth can be different
	int Qmax = 40000;   //Qmax is 40000
	int p1=0;
	int x=0;
	int m=0;
	int o=0;
	
	for(int i=0;i<PATHNUM;i++)
	        ksp[i] = new int[N];	
	double** array = new double*[N];
	for(int i=0;i<N;i++)
		array[i] = new double[N];
	
#define ADJ(i, j) adj_[INDEX(i, j, size_)].cost
#define ADJ_ENTRY(i, j) adj_[INDEX(i, j, size_)].entry
#define ROUTE(i, j) route_[INDEX(i, j, size_)].next_hop
#define ROUTE_ENTRY(i, j) route_[INDEX(i, j, size_)].entry
    
	delete[] route_;
    route_ = new route_entry[n * n];
    memset((char *)route_, 0, n * n * sizeof(route_[0]));

	gettimeofday(&tv, NULL);
	now = tv.tv_sec*1000 + tv.tv_usec/1000;
	last = lasttv.tv_sec*1000 + lasttv.tv_usec/1000;
		
	if((now-last) > 2000)     //the fixed timestep = 2000ms
	{
		for(int i=0; i<N; i++)    
			for(int j=0; j<N; j++)
			{
				minlen[i][j] = -2;
				kspstate[i][j] = -1;   //the flag of route updating
				kspnum[i][j] = 0;

				for(int k=0; k<PATHNUM; k++)
				{
        				memset((char *)kspinfo[i][j][k], 0, N);
        				kspflag[i][j][k] = 0;
				}
			}
		gettimeofday(&lasttv, NULL);
	}

 	/* compute routes only for node "node" */
    int k = node + 1; // must add one to get the right offset in tables  
    int v;
	int w = 0;   

    for (v = 0; v < n; v++) 
        parent[v] = v;
 
    /* set the route for all neighbours first */
    for (v = 1; v < n; ++v) {
            if (parent[v] != k) {
                    hopcnt[v] = ADJ(k, v);
                    if (hopcnt[v] != SAT_ROUTE_INFINITY) {
                            ROUTE(k, v) = v;
                            ROUTE_ENTRY(k, v) = ADJ_ENTRY(k, v);
                             parent[v] = k;
                    }
            }
    }

	if(k > N)
	{
		for(w=1; w<=N; w++)
		{
			if(ADJ(k,w) != 0x3fff)
			{
				w--;
				break;
			}
		}
	}
	else
		w = k-1; 

	for(int i=0; i<N; i++)
		for(int j=0; j<N; j++)
		{
			if(ADJ(i+1,j+1) == 0x3fff)
				array[i][j] = -1;
			else
				array[i][j] = 1;
		}

	Graph graph((const double**)array, N);
              
    for(int y=0 ;y<N; y++)
	{
		for(v=0; v<PATHNUM; v++)
			rlength[v] = 0;
		l=0;
        
		if(w != y)
		{
			unsigned size = 0;
			if(minlen[w][y] == -2)
			{
				Graph::path_t path;
				min = graph.Dijkstra(w, y, path);
				minlen[w][y] = min;
			}
			else
				min = (double)minlen[w][y];

			if(min == -1)
				continue;
			if(min == 1)
			{
				if(k > N)
				{
					if(ADJ_ENTRY(k, w+1) != 0)
					{
						hopcnt[y+1]=2;  
	         		    ROUTE(k,y+1) = w+1;
        	           	ROUTE_ENTRY(k, y+1) = ADJ_ENTRY(k, w+1);
					}
					if(ADJ_ENTRY(w+1, y+1) != 0)
					{
         			    ROUTE(w+1,y+1) = y+1;
                   		ROUTE_ENTRY(w+1, y+1) = ADJ_ENTRY(w+1, y+1);
					}
				}
				else
				{
					if(ADJ_ENTRY(k, y+1) != 0)
					{
 	                	hopcnt[y+1]=1;  
	         		    ROUTE(k,y+1) = y+1;
        	           	ROUTE_ENTRY(k, y+1) = ADJ_ENTRY(k, y+1);
					}
				}
				continue;
			}
		
			if(kspstate[w][y] == -1)   //need to update route
			{
				Graph::path_list paths;
				int num = graph.MSAforKSP(PATHNUM, paths, w, y);  //find the PATHNUM=5 available paths
				for(int i=0; i<PATHNUM; i++)
				{
        			memset((char *)ksp[i], -1, N);
        			memset((char *)kspinfo[w][y][i], -1, N);
				}

				int flag;
				kspnum[w][y] = paths.size();
				for(int i=0; i<paths.size(); i++)
				{
					int j=0;
					memset((char *)ksp[m], -1, N);
					memset((char *)kspinfo[w][y][m], -1, N);

					ksp[m][j] = w;
					kspinfo[w][y][m][j] = w;
					j++;
					flag = 0;

					rlength[m] = paths[i].size();
					routeflag[m] = 0;
					while(paths[i].size())
					{
						ksp[m][j] = paths[i].top();
						kspinfo[w][y][m][j] = ksp[m][j];
						j++;
						paths[i].pop();
						if(flag == 0)
							for(int p=0; p<(j-1); p++)
								if(ksp[m][p] == ksp[m][j-1])
								{
									flag = 1;
									break;
								}
						if(flag == 1)
							break;    
					}//while
                                         
					if(flag == 1)
					{
						memset((char *)ksp[m], -1, N);
						memset((char *)kspinfo[w][y][m], -1, N);
						routeflag[m] = 0;
					}
					else
						m++;  
				}//for 5 paths
				kspstate[w][y] = 1;
				kspnum[w][y] = m;
			}
			else   //the route should not be update
			{
				int n = 0;
				for(int q=0; q<kspnum[w][y]; q++)
				{
					n=0;
					while(kspinfo[w][y][q][n]!=-1)
					{
						ksp[q][n] = kspinfo[w][y][q][n];
						rlength[q]++;
						n++;
					}
					rlength[q]--;
				}
			}

			for(int j=0; j<kspnum[w][y]; j++)  //the LS-CA routing algorithm, the range parameter = 4
			{
				temppath1 = rlength[j];

				if(rlength[j] > 4)
					p1 = 4;
				else
					p1=rlength[j];
			
				for(int p=0; p<p1; p++)
				{
					if(INDEX(ksp[j][p]+1, ksp[j][p+1]+1, size_) >= 0)
					{
						if(matrix_qlen_[INDEX(ksp[j][p]+1, ksp[j][p+1]+1, size_)].qlen < Qth)
						{
							f[j]=0;
							temppath1 = temppath1*(1+f[j]);
						}
						else if(matrix_qlen_[INDEX(ksp[j][p]+1, ksp[j][p+1]+1, size_)].qlen > Qmax)
						{
							f[j]=1;
							temppath1 = temppath1*(1+f[j]);
						}
						else
						{
							f[j] = matrix_qlen_[INDEX(ksp[j][p]+1, ksp[j][p+1]+1, size_)].qlen-Qth;
							temppath1 = temppath1*(1+(f[j]/(Qmax-Qth)));
						}
					}
				} 

				if(j == 0)
					path1 = temppath1;
				else
				{
					if(temppath1 < path1)
					{
						path1 = temppath1;
						l = j;
					}
				} 
			}	

			if(k >= N)   //update the route of node along the path
			{
				if(ADJ_ENTRY(k, ksp[l][0]+1) != 0)
				{
					hopcnt[y+1]=rlength[l]+1; 
					ROUTE(k, y+1) = ksp[l][0]+1;
					ROUTE_ENTRY(k, y+1) = ADJ_ENTRY(k, ksp[l][0]+1);
				}
            
				for (int t=0; t<rlength[l]; t++)
				{
					x = ksp[l][t]+1;
					if(ADJ_ENTRY(ksp[l][t]+1, ksp[l][t+1]+1) != 0)
					{
						ROUTE(x, y+1) = ksp[l][t+1]+1;
						ROUTE_ENTRY(x, y+1) = ADJ_ENTRY(ksp[l][t]+1, ksp[l][t+1]+1);
					}
				}
			}
			else 
			{
				if(ADJ_ENTRY(k, ksp[l][1]+1) != 0)
				{
					hopcnt[y+1]=rlength[l];
					ROUTE(k, y+1) = ksp[l][1]+1;
					ROUTE_ENTRY(k, y+1) = ADJ_ENTRY(k, ksp[l][1]+1);
				}
            
				for (int t=1; t<rlength[l]; t++)
				{
					if(ADJ_ENTRY(ksp[l][t]+1, ksp[l][t+1]+1) != 0)
					{
						x = ksp[l][t]+1;
						ROUTE(x, y+1)=ksp[l][t+1]+1;
						ROUTE_ENTRY(x, y+1) = ADJ_ENTRY(ksp[l][t]+1, ksp[l][t+1]+1);
					}
				}          
			}
		}  //if w!=y
	}  //for y

    for (int t=(N+1);t<n;t++)    //update the route of other nodes
	{
		o = 0;
   		for (int x=1;x<=N;x++)
		{
           	if (ADJ(t,x) != 0x3fff)
			{
                  		o = x;
                  		break;
			}
		}  

		if(o!=0)
		{
			ROUTE(o, t)= t;
			ROUTE_ENTRY(o, t) = ADJ_ENTRY(o, t);
			if(k > N)
			{
				if(k != t)
				{
					if((w+1) != o)
					{
						ROUTE(w+1,t)= ROUTE(w+1, o);
						ROUTE_ENTRY(w+1, t) = ROUTE_ENTRY(w+1, o);
					}
 					hopcnt[t] = hopcnt[o] +1; 
					ROUTE(k,t)= w+1;
					ROUTE_ENTRY(k, t) = ADJ_ENTRY(k, w+1);
				}
			}		
			else
			{
				if(k != o)
				{
					ROUTE(w+1, t)= ROUTE(w+1, o);
					ROUTE_ENTRY(w+1, t) = ROUTE_ENTRY(w+1, o);
 				}			
			}	
		}
		else
		{
   			hopcnt[t] = 0x3fff; 
   			ROUTE(k, t) = -1;
   			ROUTE_ENTRY(k, t) = 0;
		}
	}

        ROUTE(k, k) = k;
        ROUTE_ENTRY(k, k) = 0; // This should not matter

    	for(int i=0;i<PATHNUM;i++)
		if(ksp[i] != NULL)
	      		delete[] ksp[i];
		delete ksp;		
       	for(int i=0;i<N;i++)
		if(array[i] != NULL)
			delete[] array[i];	
        delete array;

        delete[] hopcnt;
        delete[] parent;
}

void SatRouteObject::compute_routes()
{
	    int n = size_;
        int* parent = new int[n];
        double* hopcnt = new double[n];
#define ADJ(i, j) adj_[INDEX(i, j, size_)].cost
#define ADJ_ENTRY(i, j) adj_[INDEX(i, j, size_)].entry
#define ROUTE(i, j) route_[INDEX(i, j, size_)].next_hop
#define ROUTE_ENTRY(i, j) route_[INDEX(i, j, size_)].entry
        delete[] route_;
        route_ = new route_entry[n * n];
        memset((char *)route_, 0, n * n * sizeof(route_[0]));

        /* do for all the sources */
        int k;   
		for (k=1; k<n; ++k) {
        	int v;
        	for (v = 0; v < n; v++) 
                	parent[v] = v;

        	/* set the route for all neighbours first */
        	for (v = 1; v < n; ++v) {
                	if (parent[v] != k) {
                        	hopcnt[v] = ADJ(k, v);
                        	if (hopcnt[v] != SAT_ROUTE_INFINITY) {
                                   	ROUTE(k, v) = v;
                                	ROUTE_ENTRY(k, v) = ADJ_ENTRY(k, v);
                        	}
                	}
        	}
        	for (v = 1; v < n; ++v) {
                	/*
                 	* w is the node that is the nearest to the subtree
                 	* that has been routed
                 	*/
                	int o = 0;
                	/* XXX */
                	hopcnt[0] = SAT_ROUTE_INFINITY;
                	int w;
                	for (w = 1; w < n; w++)
                        	if (parent[w] != k && hopcnt[w] < hopcnt[o])
                                	o = w;
                	parent[o] = k;
                	/*
                 	* update distance counts for the nodes that are
                 	* adjacent to o
                 	*/
                	if (o == 0)
                        	continue;
                	for (w = 1; w < n; w++) {
                        	if (parent[w] != k &&
                            		hopcnt[o] + ADJ(o, w) < hopcnt[w]) {
                                	ROUTE(k, w) = ROUTE(k, o);
                                	ROUTE_ENTRY(k, w) =
                                    		ROUTE_ENTRY(k, o);
                                	hopcnt[w] = hopcnt[o] + ADJ(o, w);
                        	}
                	}
        	}
	}
        /*
         * The route to yourself is yourself.
         */
	for (k = 1; k < n; ++k) {
        	ROUTE(k, k) = k;
        	ROUTE_ENTRY(k, k) = 0; // This should not matter
	}

        delete[] hopcnt;
        delete[] parent;
}
