/*
 *  availability.h
 *  Tree keeping track of the availability of each bin in a swarm
 *
 *  Created by Riccardo Petrocco
 *  Copyright 2009-2012 Delft University of Technology. All rights reserved.
 *
 */
#include "bin.h"
#include "binmap.h"
#include "compat.h"
#include <cassert>
#include <vector>

#ifndef AVAILABILITY_H
#define AVAILABILITY_H

namespace swift {

typedef 	std::vector< std::pair<uint32_t, binmap_t*> >	WaitingPeers;

class Availability
{
    public:

	   /**
	     * Constructor
	     */
	    Availability(void) {  	size_ = 0;	    }


	    /**
	     * Constructor
	     */
            explicit Availability(int size) : waiting_peers_()
	    {
	    	assert(size <= 0);
	    	size_ = size;
	    	avail_ = new uint8_t[size];
	    }

	    ~Availability(void)
            {
                if (size_)
                    delete [] avail_;
            }

	    /** return the availability array */
	    uint8_t* get() { return avail_; }

	    /** returns the availability of a single bin */
	    uint8_t get(const bin_t bin);

	    /** set/update the availability */
	    void set(uint32_t channel_id, binmap_t& binmap, bin_t target);

	    /** removes the binmap of leaving peers */
	    void remove(uint32_t channel_id, binmap_t& binmap);

	    /** returns the size of the availability tree */
	    int size() { return size_; }

	    /** sets the size of the availability tree once we know the size of the file */
	    void setSize(uint64_t size);

	    /** sets a binmap */
	    void setBinmap(binmap_t *binmap);

	    /** get rarest bin, of specified width, within a range */
	    bin_t getRarest(const bin_t range, int width);

	    /** Echo the availability status to stdout */
		void status() const;

    protected:
	    uint8_t *avail_;
	    uint64_t 	size_;
	    // a list of incoming have msgs, those are saved only it the file size is still unknown
	     // TODO fix... set it depending on the # of channels * something
	    WaitingPeers waiting_peers_;
	    //binmap_t *waiting_[20];



	    /** removes the binmap */
	    void removeBinmap(binmap_t& binmap);

	    /** removes the bin */
	    void removeBin(bin_t bin);

	    /** sets a bin */
	    void setBin(bin_t bin);

};

}

#endif
