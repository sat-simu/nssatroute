/*===============================================================================
<summary>
	<filename> Graph.h </filename>
    <copyright> Copyright (c) 2006 David D. All Rights Reserved. Revised by Xin Xu.</copyright> 
    <guide>
		Graph Data Structure.			

		Look out: If the input graph isn't directed acyclic
		graph, the MSAforKSP maybe throw some exceptions.
		What's more, the input graph must have only one START
		node. If the origin graph has more than one START node,
		you need add a 'virtual' START node to input graph 
		which should be linked to the real START nodes. To the 
		END node, do the same as START node.

		* Any suggestion, contact with SharperDavid@hotmail.com.
	</guide>
    <version> 1.1 </version>
	<date> 2022.9 </date>
<summary>
=================================================================================*/

#ifndef GRAPH_H
#define GRAPH_H

#include <iostream>
#include <vector>
#include <stack>

using namespace std;

namespace Mido
{
	namespace Utility
	{
		class Graph
		{
		public:
			typedef stack<unsigned> path_t;			// the top is the first node
			typedef vector<path_t>  path_list;		// the paths are sorted by ASC
			typedef vector< vector<double> > dag_t; // the two dimension array storing a DAG


			/// Input array: there must be only a start node!
			///	if the value of one element of array < 0, indicates there are no arc.
			Graph();
			Graph( const dag_t& array );
			Graph( const double **array , unsigned N );
			~Graph();

			/// Reset the directed acyclic graph (DAG).
			void Restart( const dag_t& array );
			void Restart( const double **array , unsigned N );

			/// Find the shortest path from node 0 to node N-1.
			/// Dijkstra Algorithm Implementation.			
			/// Parameter <path> return the shortest path.
			///	If fails, return -1, or return the shortest distance.			
			double Dijkstra( path_t& path );
			/// Find the shortest path from the named start node to the named end node.
			/// Parameter <start> - start node.
			/// Parameter <end> - end node. 
			/// Make sure <end> != <start>.			
			double Dijkstra( unsigned start , unsigned end , path_t& path );

			/// Find the k shortest paths (KSP) from node 0 to N-1.						
			/// Martins' Algorithm (deletion algorithm) Implementation.
			/// Parameter <paths> return all the shortest paths.			
			/// If fails, return 0, or return the real number of all the shortest paths.								
		//	int MSAforKSP( unsigned k , path_list& kpaths );
			int MSAforKSP( unsigned k , path_list& kpaths, unsigned start, unsigned end );

			/// Output the content of "_array" for debug.
			void Output( ostream& out = cerr );

		private:
			/// Default is to compute the shortest distance from node 0 to node N-1.
			double dijkstra( int* paths , unsigned start = 0 , unsigned end = 0 );
			double dijkstra( int* paths , double* dists );

			/// Add a node to graph.
			/// Return the number of new node.
			unsigned addNode( unsigned ni , int preni );		

		private:
			unsigned _N;	 // original size of "_array", it's fixed.
			unsigned _size;	 // size of "_array", because the "_array" maybe be reallocated. 
			dag_t    _array; // dynamic two dimension array
				
		};
	}
}

#endif	// GRAPH_H
