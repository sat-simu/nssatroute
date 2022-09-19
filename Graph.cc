/*===============================================================================
<summary>
	<filename> Graph.cc </filename>
    <copyright> Copyright (c) 2006 David D. All Rights Reserved. Revised by Xin Xu.</copyright> 
    <guide>
		Graph Functions.			
	
	</guide>
    <version> 1.1 </version>
	<date> 2022.9 </date>
<summary>
=================================================================================*/
#include "Graph.h"

using namespace Mido::Utility;

#define INFINITY 0xFFFFFFFF


Graph::Graph() : _N(0), _size(0)
{
}

Graph::Graph(const dag_t& array)
{
	_N = _size = array.size();
	_array.resize(_size);
	for(int i=0;i<_size;i++)
	{
		_array[i].resize(_size);
		for(int j=0;j<_size;j++)
			_array[i][j] = array[i][j];
	}
}

Graph::Graph(const double **array, unsigned N) : _N(N), _size(N)
{	
	_array.resize(_size);
	for(int i=0;i<_size;i++)
	{
		_array[i].resize(_size);
		for(int j=0;j<_size;j++)
			_array[i][j] = array[i][j];
	}

}

Graph::~Graph()
{	
}

void Graph::Restart(const dag_t& array)
{
	_array.clear();

	_N = _size = array.size();
	_array.resize(_size);
	for(int i=0;i<_size;i++)
	{
		_array[i].resize(_size);
		for(int j=0;j<_size;j++)
			_array[i][j] = array[i][j];
	}
}

void Graph::Restart(const double** array,unsigned N)
{
    _array.clear();

	_N = _size = N;
	_array.resize(_size);
	for(int i=0;i<_size;i++)
	{
		_array[i].resize(_size);
		for(int j=0;j<_size;j++)
			_array[i][j] = array[i][j];
	}
}

double Graph::Dijkstra( path_t& path )
{
	int* paths = new int[_size];
	double min = dijkstra(paths);
   if(min < 0) { delete[] paths; return -1;}

	// parse the shortest path	
	int i = _size - 1;	
	while(i>=0)
	{		
		path.push(i);
		i=paths[i];			
	}
	// push the start node
	path.push(0); 
	
	delete[] paths;
	return min;
}

double Graph::Dijkstra( unsigned start , unsigned end , path_t& path )
{
	if(end == start || start >= _size) return -1;

	int* paths = new int[_size];
	double min = dijkstra(paths,start,end);
    if(min < 0) { delete[] paths; return -1;}

	// parse the shortest path
	if(end > _size-1) end = _size - 1;
	int i = end;	
	while(i>=0)
	{		
		path.push(i);
		i=paths[i];			
	}
	// push the start node
	if(_array[start][path.top()]>=0)
		path.push(start);	
	else 
		{ delete[] paths; return -1;}

    delete[] paths;
	return min;
}

void Graph::Output(ostream& out)
{
	for(int i=0;i<_size;i++)
	{
		out.width(2);
		out << std::right << i << " ";
		for(int j=0;j<_size;j++)
		{
			out.width(10); //out.precision(8);
			out << std::right <<_array[i][j] <<" ";
		}
		out << endl;
	}
}

/*
    S       -- START node.
	T		-- END node
	Path[]  -- Path[i]=j indicates the previous node of node i is j. Path[i]=-1 indicates node i
	           has not previous node, e.g. START node. It could be expanded dynamically.
    Dist[]  -- store the lengths of the shortest pathes from START node to END node. It could be
			   expanded dynamically.Dist[i]=INFINITY indicates there is not a path from START
			   node to node i.
	Prime[] -- Prime[i] indicates node Prime[i] is the prime node of node i. Prime[i]=-1 indicates
	           the node i has not prime node.
	Base[]  -- In opposition to Prime[i], node Base[i] is the original node of node i, that is to say, 
	           node i is the prime node of node Base[i].
 */

int Graph::MSAforKSP( unsigned k ,  path_list& kpaths, unsigned start, unsigned end ){	
	/* Initialize */	
	vector<int> Path, Prime, Base;
	vector<double> Dist;
	Path.resize(_size); 
	Prime.resize(_size);
	Base.resize(_size);
	Dist.resize(_size);

	for(int i=0;i<_size;i++)
	{ Prime[i] = -1; Base[i] = i; }
	
	/* Find the shortest path firstly */	
	if( dijkstra(&Path[0],start, end) < 0 ) return 0;    
	path_t path; 
	int j = end;	  

	while(j>=0)
	{		
		path.push(j); j=Path[j];			
	}
	kpaths.push_back(path); // store the shortest path

	/* Find the 2th - kth shortest paths */
	int ki = 1;
	while( ki < k )
	{
		/* Find the first node with more than a single incoming arc */
		unsigned nh = 0;
		while( path.size() )
		{
			unsigned node = path.top(); path.pop();
			int count = 0;
			for( int i=0; i<_size; i++ )
			{
				if( _array[i][node] >= 0 ) count++;
				if( count > 1 ) break;
			}
			
			if( count > 1 ) { nh = node; break; }
		}

		if( !nh ) break; // there is NOT an alternative path, exit!

		unsigned ni = 0;
		/* Add the first prime node to graph */
		if( Prime[nh] < 0 )
		{
			unsigned nh1 = addNode(nh,Path[nh]);

			/* compute the minimal distance from node 0 to nh1 */
			double min_dist = (unsigned)INFINITY;
			int min_node = -1;
			for(int i=0;i<_size-1;i++)
			{
				if( Dist[i] + (unsigned)_array[i][nh1] < min_dist )
				{
					min_dist = Dist[i] + _array[i][nh1];
					min_node = i;
				}
			}
			
			Dist.push_back(min_dist);
			Path.push_back(min_node);
			Prime.push_back(-1);
			Prime[nh] = nh1;

			/* record the base node */
			unsigned basei = nh;
			while(basei != Base[basei])
				basei = Base[basei];
			Base.push_back(basei);

			if(path.size())
			{ ni = path.top(); path.pop(); }
		}
		/*  Get node ni, it must meet it's the first node following nh in path, but its prime node ni` is NOT in graph */
		else
		{
			while( path.size() )
			{
				ni = path.top(); path.pop();
				if(Prime[ni] < 0) break;				
			}
		}		

		while(ni>=0)   
		{
			unsigned ni1 = addNode(ni,Path[ni]);

			if(Path[ni]>=0)				
			if(Prime[Path[ni]]>=0)				
				_array[Prime[Path[ni]]][ni1] = _array[Path[ni]][ni];	// add the arc -- (ni-1`,ni`)			

			/* compute the minimal distance from node 0 to ni1 */
			double min_dist = (unsigned)INFINITY;
			int min_node = -1;
			for(int i=0;i<_size-1;i++)
			{
				//cout << Dist[i] << " " << _array[i][ni1] << endl; // for debug
				if( Dist[i] + (unsigned)_array[i][ni1] < min_dist )
				{
					min_dist = Dist[i] + _array[i][ni1];
					min_node = i;
				}
			}
			
			Dist.push_back(min_dist);
			Path.push_back(min_node);
			Prime.push_back(-1);
			Prime[ni] = ni1;

			/* record the base node */
			unsigned basei = ni;
			while(basei != Base[basei])
				basei = Base[basei];
			Base.push_back(basei);

			if( !path.size() ) break;
			ni = path.top(); path.pop();			
		}

		/* get the kth shortest path */			
		if( !ni ) ni = nh; // if nh is just the end node.
		path_t temp;		
		int j = Prime[ni];
		while(j>=0)
		{		
			path.push(j); temp.push(Base[j]); j=Path[j];
		}
		if(temp.size()<2) break; 
		kpaths.push_back(temp);  // store the kth shortest path

		ki++;
		//this->Output(); // for debug
	}	
	
	return ki;
}


/*
	Look out: Dijkstra algorithm doesn't assure the
	generated tree from graph is minimal generated tree.
*/
/// Look out: the returned paths doesn'n include the start node!
double Graph::dijkstra( int* paths , unsigned start , unsigned end )
{	
	int* Used = new int[_N];		   // label the used nodes, 0 - indicates not used.
	double* Dist = new double[_N];     // store the min distances from start node to node indicated by current suffix.
	/* Initialize */	
	unsigned i;
	for(i=0;i<_N;i++)
	{
		paths[i]= -1;	
		Used[i] = 0;
		Dist[i] = (_array[start][i] < 0.0) ? INFINITY : _array[start][i]; 
	}	
	Used[start] = 1;		           // label the start node
	
	unsigned count = 0;	
	while(count++ < _N)
	{		
		int min_node = -1;
		double min_dist = (unsigned)INFINITY;

		/* Select */
		for(i=0;i<_N;i++)
		{
			if(Used[i] > 0)continue;   // ignore the used node
			
			if(Dist[i] < min_dist)
			{
				min_dist = Dist[i];
				min_node = i;
			}
		}
		if(min_dist == INFINITY)break;

		/* Record shortest path from the current node to start node */
		if(min_node >= 0)
		{			
			Used[min_node]  = 1;
			Dist[min_node]  = min_dist;			
		}

		if(min_node >= (int)_N)break;   

		/* Adjust */
		for(i=0;i<_N;i++)
		{
			if( Used[i] > 0)continue;  // ignore the used node

			double w = (unsigned)(_array[min_node][i] < 0.0 ? INFINITY : _array[min_node][i]);
			if( min_dist + w < Dist[i] )
			{
				Dist[i] = min_dist + w;
				paths[i] = min_node;
			}
		}       
	}	

	double mdist = Dist[_N-1];
	if( end != start && end < _N)
		mdist = Dist[end];

	delete[] Used;
	delete[] Dist;

	return (signed)(mdist == INFINITY ? -1 : mdist);
}

double Graph::dijkstra( int* paths , double* dists )
{	
	int* Used = new int[_N]; 	       // label the used nodes, 0 - indicates not used.
	double* Dist = dists;

	/* Initialize */	
	unsigned i;
	for(i=0;i<_N;i++)
	{
		paths[i]= -1;	
		Used[i] = 0;
		Dist[i] = (_array[0][i] < 0.0) ? INFINITY : _array[0][i]; 
	}	
	Used[0] = 1;		               // label the start node
	
	unsigned count = 0;	
	while(count++ < _N)
	{		
		int min_node = -1;
		double min_dist = (unsigned)INFINITY;

		/* Select */
		for(i=0;i<_N;i++)
		{
			if(Used[i] > 0)continue;   // ignore the used node
			
			if(Dist[i] < min_dist)
			{
				min_dist = Dist[i];
				min_node = i;
			}
		}
		if(min_dist == INFINITY)break;

		/* Record shortest path from the current node to start node */
		if(min_node >= 0)
		{			
			Used[min_node]  = 1;
			Dist[min_node]  = min_dist;			
		}
		if(min_node >= (int)_N-1)break;

		/* Adjust */
		for(i=0;i<_N;i++)
		{
			if( Used[i] > 0)continue;  // ignore the used node

			double w = (unsigned)_array[min_node][i];// < 0.0 ? INFINITY : _array[min_node][i];
			if( min_dist + w < Dist[i] )
			{
				Dist[i] = min_dist + w;
				paths[i] = min_node;
			}
		}       
	}

	delete[] Used;
	return (signed)Dist[_N-1];// == INFINITY ? -1 : Dist[_N-1];
}

/*
	Here, using vector is more efficient than 2-dimension dynamic array.
*/
unsigned Graph::addNode(unsigned ni,int preni)
{
	vector<double> newRow;
	for(int i=0;i<_size;i++)
	{
		if(i != preni)
			_array[i].push_back(_array[i][ni]);
		else
			_array[i].push_back(-1);

		newRow.push_back(-1);
	}

	newRow.push_back(-1);
	_array.push_back(newRow);

	return _size++;
}
