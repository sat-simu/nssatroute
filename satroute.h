/*
 * Contributed by Tom Henderson, UCB Daedalus Research Group, June 1999
 * Revised by Xin Xu, Sep 2022.
 */

#ifndef ns_satroute_h_
#define ns_satroute_h_

#include <iostream>  
#include <vector> 
#include <stack> 
#include "packet.h"  
#include "ip.h"   
#include <agent.h>
#include "route.h"
#include "node.h"
#include "Graph.h"  

using namespace std;
using namespace Mido::Utility;

#define ROUTER_PORT      0xff
#define SAT_ROUTE_INFINITY 0x3fff

const int N = 66;  
#define PATHNUM 5 

struct Matrix_Qlen {
        int qlen;
        double timestamp;
};  

// Entry in the forwarding table
struct slot_entry {
	int next_hop;	
	NsObject* entry;
}; 

struct hdr_SatDV {
	u_int32_t mv_;

	static int offset_;
	inline static int& offset() { return offset_; }
	inline static hdr_SatDV* access(const Packet* p) {
		return (hdr_SatDV*) p->access(offset_);
	}

	u_int32_t& metricsVar() { return mv_; }
};

class SatNode;
//
//  Currently, this only implements centralized routing.  However, by 
//  following the examples in the mobility code, one could build on this
//  agent to make it a distributed routing agent
//
class SatRouteAgent : public Agent {
public:
  SatRouteAgent();
  ~SatRouteAgent();
  int command(int argc, const char * const * argv);

  // centralized routing
  void clear_slots();
  void install(int dst, int next_hop, NsObject* p);
  SatNode* node() { return node_; }
  int myaddr() {return myaddr_; }
  
protected:
  virtual void recv(Packet *, Handler *);
  void forwardPacket(Packet*);
  int myaddr_;           // My address-- set from OTcl

  // centralized routing stuff
  int maxslot_;
  int nslot_;
  slot_entry* slot_;	// Node's forwarding table 
  void alloc(int);	// Helper function
  SatNode* node_;
  
};

////////////////////////////////////////////////////////////////////////////

// A global route computation object/genie  
// This class performs operations very similar to what "Simulator instproc
// compute-routes" does at OTcl-level, except it performs them entirely
// in C++.  Single source shortest path routing is also supported.
class SatRouteObject : public RouteLogic {
public:
  SatRouteObject(); 
  static SatRouteObject& instance() {
	return (*instance_);            // general access to route object
  }
  void recompute();
  void recompute_node(int node);
  int command(int argc, const char * const * argv);        
  int data_driven_computation() { return data_driven_computation_; } 
  void insert_link(int src, int dst, double cost);
  void insert_link(int src, int dst, double cost, void* entry);
  int wiredRouting() { return wiredRouting_;}
//void hier_insert_link(int *src, int *dst, int cost);  // support hier-rtg?

protected:
  void compute_topology();
  void populate_routing_tables(int node = -1);
  int lookup(int src, int dst);
  void* lookup_entry(int src, int dst);
  void node_compute_routes(int node);
  void compute_routes(); 

  static SatRouteObject*  instance_;
  int metric_delay_;
  int suppress_initial_computation_;
  int data_driven_computation_;
  int wiredRouting_;
  Matrix_Qlen matrix_qlen_[128*128]; 
  int f[N];
  int rlength[PATHNUM];
  int routeflag[PATHNUM];
  double minlen[N][N]; 
  static int kspstate[N][N];
  int kspnum[N][N];
  int kspflag[N][N][PATHNUM];    
  int kspinfo[N][N][PATHNUM][N];
};

#endif
