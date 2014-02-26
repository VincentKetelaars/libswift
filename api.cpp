/*
 *  api.cpp
 *  Swift top-level API implementation
 *
 *  Created by Victor Grishchenko on 3/6/09.
 *  Copyright 2009-2016 TECHNISCHE UNIVERSITEIT DELFT. All rights reserved.
 *
 */


#include "swift.h"
#include "swarmmanager.h"

using namespace std;
using namespace swift;


#define api_debug	false



/*
 * Local functions
 */

void StartLibraryCleanup()
{
	if (ContentTransfer::cleancounter == 0)
	{
		// Arno, 2012-10-01: Per-library timer for cleanup on transfers
		evtimer_assign(&ContentTransfer::evclean,Channel::evbase,&ContentTransfer::LibeventGlobalCleanCallback,NULL);
		evtimer_add(&ContentTransfer::evclean,tint2tv(TINT_SEC));
		ContentTransfer::cleancounter = 481;
	}
}

/*
 * Global Operations
 */

int     swift::Listen(Address addr, std::string device)
{
	/*
	 * Listen policy:
	 * In principal all addresses will be attempted. A failure to bind results in the program quitting.
	 * All accepted addresses will be stored, as well as information on their interfaces.
	 * In case a new address has the same ip address and port number as a consisting socket,
	 * binding will only continue if there was an error with this socket. (The socket is then also removed)
	 * In case a new address is accompanied by a device name, the latter is compared to other sockets.
	 * If one such exists already and has an erred last time, it will be removed. A new socket on the same device is allowed.
	 * The same thing applies to an incoming ip address with different port number.
	 */
	evutil_socket_t sock_to_kill = -1;
	evutil_socket_t sock  = Channel::GetSocket(addr);
	if (sock != -1) {
		if (api_debug)
			fprintf(stderr, "Socket %s is already running!\n", addr.str().c_str());
		if (Channel::socket_if_info_map[sock].err != 0) { // We assume here that we are dealing with the same interface!
			struct evbuffer *sendevbuf = evbuffer_new();
			Channel::SendTo(sock, Address("127.0.0.1:12345"), sendevbuf); // Send fake message to check if interface is indeed up and socket running
			evbuffer_free(sendevbuf);
		}
		return -1; // There is no point in adding the same address
	}

	sock  = Channel::GetSimilarSocket(device, addr); // Socket with same device and/or ip
	if (sock != -1) {
		if (api_debug)
			fprintf(stderr, "We have a socket %s for this device with error %d!\n",
					Channel::socket_if_info_map[sock].address.str().c_str(), Channel::socket_if_info_map[sock].err);
		if (Channel::socket_if_info_map[sock].err != 0 &&
			addr.ipstr(false).compare(Channel::socket_if_info_map[sock].address.ipstr(false)) != 0) { // Unequal IPs
			sock_to_kill = sock; // Error and not same ip, so we kill it
		}
		// If it is the same IP, we allow it
	}

	if (sock_to_kill != -1) {
		if (api_debug)
			fprintf(stderr, "This socket %s has problems, so we will replace it!\n",
					Channel::socket_if_info_map[sock_to_kill].address.str().c_str());
		channels_t cbs = Channel::GetChannelsBySocket(sock_to_kill);
		channels_t::iterator iter;
		for (iter=cbs.begin(); iter!=cbs.end(); iter++) {
			if ((*iter) != NULL)
				(*iter)->Schedule4Delete();
		}
		Channel::CloseSocket(sock_to_kill);
	}

	struct event *evrecv = new struct event;

	// Only do StartLibraryCleanup once, otherwise the same event is added to base again
	if (Channel::sock_count == 0)
		StartLibraryCleanup();

	sckrwecb_t cb;
	cb.may_read = &Channel::LibeventReceiveCallback;
	cb.sock = Channel::Bind(addr, cb, device);
	// There might be a totally different IP address in use than suggested by addr
	if (cb.sock != INVALID_SOCKET && addr.port() == 0) {
		if (addr.get_family() == AF_INET) {
			struct sockaddr_in sin;
			socklen_t len = sizeof(sin);
			if (getsockname(cb.sock, (struct sockaddr *)&sin, &len) == -1)
				perror("getsockname");
			Channel::socket_if_info_map[cb.sock].address.set_port(ntohs(sin.sin_port)); // Update the port number
		}
		if (addr.get_family() == AF_INET6) {
			struct sockaddr_in6 sin6;
			socklen_t len = sizeof(sin6);
			if (getsockname(cb.sock, (struct sockaddr *)&sin6, &len) == -1)
				perror("getsockname");
			Channel::socket_if_info_map[cb.sock].address.set_port(ntohs(sin6.sin6_port)); // Update the port number
		}
	}
	if (cb.sock != INVALID_SOCKET) {
		// This print will be read by Dispersy to ensure that we have a new working socket
		fprintf(stderr,"swift::Listen addr %s\n", Channel::socket_if_info_map[cb.sock].address.str().c_str() );
		Channel::updateSocketIfInfo(cb.sock, 0); // In addition we do a callback if available
	}
	// swift UDP receive
	event_assign(evrecv, Channel::evbase, cb.sock, EV_READ|EV_PERSIST,
			cb.may_read, NULL);
	event_add(evrecv, NULL);
	return cb.sock;
}

void swift::CleanAndClose() {
	if (api_debug)
		fprintf(stderr,"swift::CleanAndClose\n");
	// Arno, 2012-01-03: Close all transfers
	tdlist_t tds = GetTransferDescriptors();
	tdlist_t::iterator iter;
	for (iter = tds.begin(); iter != tds.end(); iter++ )
		swift::Close(*iter);

	Channel::delete_rules_and_tables();

	if (Channel::debug_file && Channel::debug_file != stderr) {
		fflush(Channel::debug_file);
		fclose(Channel::debug_file);
	}

	swift::Shutdown();
}

void    swift::Shutdown()
{
	if (api_debug)
		fprintf(stderr,"swift::Shutdown\n");

	Channel::Shutdown();
}


/*
 * Per-Swarm Operations
 */


int swift::Open( std::string filename, const Sha1Hash& hash, Address tracker, bool force_check_diskvshash, bool check_netwvshash, bool zerostate, bool activate, uint32_t chunk_size)
{
	if (api_debug)
		fprintf(stderr,"swift::Open %s hash %s track %s cdisk %d cnet %d zs %d act %d cs %u\n", filename.c_str(), hash.hex().c_str(), tracker.str().c_str(), force_check_diskvshash, check_netwvshash, zerostate, activate, chunk_size );

	SwarmData* swarm = SwarmManager::GetManager().AddSwarm( filename, hash, tracker, force_check_diskvshash, check_netwvshash, zerostate, activate, chunk_size );
	if (swarm == NULL)
		return -1;
	else
		return swarm->Id();
}


void swift::Close( int td, bool removestate, bool removecontent ) {
	if (api_debug)
		fprintf(stderr,"swift::Close td %d rems %d remc%d\n", td, (int)removestate, (int)removecontent );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm)
		SwarmManager::GetManager().RemoveSwarm( swarm->RootHash(), removestate, removecontent );

	//LIVE
	LiveTransfer *lt = LiveTransfer::FindByTD(td);
	if (lt != NULL)
		delete lt;
}

int swift::Find(const Sha1Hash& swarmid, bool activate)
{
	if (api_debug)
		fprintf(stderr,"swift::Find %s act %d\n", swarmid.hex().c_str(), (int)activate );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(swarmid);
	if (swarm==NULL)
	{
		//LIVE
		LiveTransfer *lt = LiveTransfer::FindBySwarmID(swarmid);
		if (lt == NULL)
			return -1;
		else
			return lt->td();
	}
	else
	{
		if (activate)
			SwarmManager::GetManager().ActivateSwarm(swarm->RootHash());
		return swarm->Id();
	}
}


ContentTransfer *swift::GetActivatedTransfer(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::GetActivatedTransfer td %d\n", td );

	ContentTransfer *ct = NULL;
	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm == NULL)
		ct = (ContentTransfer *)LiveTransfer::FindByTD(td);
	else
		ct = swarm->GetTransfer(false); // Arno: do not activate if not already
	return ct;
}



// Local method
static ContentTransfer *FindActivateTransferByTD(int td)
{
	ContentTransfer *ct = NULL;
	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm == NULL)
		//LIVE
		ct = (ContentTransfer *)LiveTransfer::FindByTD(td);
	else
	{
		if (!swarm->Touch()) {
			swarm = SwarmManager::GetManager().ActivateSwarm( swarm->RootHash() );
			if (swarm == NULL)
				return NULL;
			if (!swarm->Touch())
				return NULL;
		}
		ct = swarm->GetTransfer();
	}
	return ct;
}


ssize_t swift::Read( int td, void *buf, size_t nbyte, int64_t offset )
{
	if (api_debug)
		fprintf(stderr,"swift::Read td %d buf %p n " PRISIZET " o %lld\n", td, buf, nbyte, offset );

	ContentTransfer *ct = FindActivateTransferByTD(td);
	if (ct == NULL)
		return -1;
	else
		return ct->GetStorage()->Read(buf, nbyte, offset);
}

ssize_t swift::Write( int td, const void *buf, size_t nbyte, int64_t offset )
{
	if (api_debug)
		fprintf(stderr,"swift::Write td %d buf %p n " PRISIZET " o %lld\n", td, buf, nbyte, offset );

	ContentTransfer *ct = FindActivateTransferByTD(td);
	if (ct == NULL)
		return -1;
	else
		return ct->GetStorage()->Write(buf, nbyte, offset);
}


/*
 * Swarm Info
 */

uint64_t swift::Size(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::Size td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm == NULL)
		return 0; //also for LIVE
	return swarm->Size();
}



bool swift::IsComplete(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::IsComplete td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm == NULL)
		return false; //also for LIVE
	return swarm->IsComplete();
}


uint64_t swift::Complete(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::Complete td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm == NULL)
		return 0; //also for LIVE
	return swarm->Complete();
}


uint64_t swift::SeqComplete( int td, int64_t offset )
{
	if (api_debug)
		fprintf(stderr,"swift::SeqComplete td %d o %ld\n", td, offset );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return 0;
		else
			return lt->SeqComplete(); // No range support for live
	}
	else
	{
		return swarm->SeqComplete(offset);
	}
}


const Sha1Hash& swift::SwarmID(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::SwarmID td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return Sha1Hash::ZERO;
		else
			return lt->swarm_id();
	}
	else
		return swarm->RootHash();
}


/** Returns the number of bytes in a chunk for this transmission */
uint32_t swift::ChunkSize( int td)
{
	if (api_debug)
		fprintf(stderr,"swift::ChunkSize td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td);
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return 0;
		else
			return lt->chunk_size();
	}
	else
		return swarm->ChunkSize();
}



tdlist_t swift::GetTransferDescriptors()
{
	if (api_debug)
		fprintf(stderr,"swift::GetTransferDescriptors\n" );
	tdlist_t filetdl = SwarmManager::GetManager().GetTransferDescriptors();
	tdlist_t livetdl = LiveTransfer::GetTransferDescriptors();
	filetdl.insert(filetdl.end(),livetdl.begin(),livetdl.end()); // append
	return filetdl;
}

void swift::SetMaxSpeed(int td, data_direction_t ddir, double speed)
{
	if (api_debug)
		fprintf(stderr,"swift::SetMaxSpeed td %d dir %d speed %lf\n", td, (int)ddir, speed );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return;
		else
		{
			// Arno, 2012-05-25: SetMaxSpeed resets the current speed history, so
			// be careful here.
			if( lt->GetMaxSpeed( ddir ) != speed )
				lt->SetMaxSpeed( ddir, speed );
		}
	}
	else
		swarm->SetMaxSpeed(ddir,speed); // checks current set speed beforehand
}

double swift::GetCurrentSpeed(int td, data_direction_t ddir)
{
	if (api_debug)
		fprintf(stderr,"swift::GetCurrentSpeed td %d ddir %d\n", td, (int)ddir );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return -1.0;
		else
			return lt->GetCurrentSpeed(ddir);
	}
	else
	{
		FileTransfer *ft = swarm->GetTransfer(false); // Arno: do not activate for this
		if (!ft)
			return -1.0;
		else
			return ft->GetCurrentSpeed(ddir);
	}
}


uint32_t swift::GetNumSeeders(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::GetNumSeeders td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return 0;
		else
			return lt->GetNumSeeders();
	}
	else
	{
		FileTransfer *ft = swarm->GetTransfer(false); // Arno: do not activate for this
		if (!ft)
			return 0;
		else
			return ft->GetNumSeeders();
	}
}


uint32_t swift::GetNumLeechers(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::GetNumLeechers td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return 0;
		else
			return lt->GetNumLeechers();
	}
	else
	{
		FileTransfer *ft = swarm->GetTransfer(false); // Arno: do not activate for this
		if (!ft)
			return 0;
		else
			return ft->GetNumLeechers();
	}
}



transfer_t swift::ttype(int td)
{
	//if (api_debug)
	//	fprintf(stderr,"swift::ttype td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm == NULL)
		return LIVE_TRANSFER; // approx of truth
	else
		return FILE_TRANSFER;
}

Storage *swift::GetStorage(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::GetStorage td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return NULL;
		else
			return lt->GetStorage();
	}
	else
	{
		FileTransfer *ft = swarm->GetTransfer(); // Must activate for this
		if (!ft)
			return NULL;
		else
			return ft->GetStorage();
	}
}

std::string swift::GetOSPathName(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::GetOSPathName td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL || lt->GetStorage() == NULL)
			return "";
		else
			return lt->GetStorage()->GetOSPathName();
	}
	else
		return swarm->OSPathName();
}

bool swift::IsOperational(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::IsOperational td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return false;
		else
			return lt->IsOperational();
	}
	else
	{
		FileTransfer *ft = swarm->GetTransfer(false);   // Arno: do not activate for this
		if (!ft)
			return false;
		else
			return ft->IsOperational();
	}
}



bool swift::IsZeroState(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::IsZeroState td %d\n", td );

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm( td );
	if (swarm == NULL)
		return false;
	else
		return swarm->IsZeroState();
}



//CHECKPOINT
int swift::Checkpoint(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::Checkpoint td %d\n", td );

	// If file, save transfer's binmap for zero-hashcheck restart
	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm == NULL)
		return -1; // also for LIVE
	FileTransfer *ft = swarm->GetTransfer(false);
	if (ft == NULL)
		return -1; // not activated
	if (ft->IsZeroState())
		return -1;

	MmapHashTree *ht = (MmapHashTree *)ft->hashtree();
	if (ht == NULL)
	{
		fprintf(stderr,"swift: checkpointing: ht is NULL\n");
		return -1;
	}

	std::string binmap_filename = ft->GetStorage()->GetOSPathName();
	binmap_filename.append(".mbinmap");
	//fprintf(stderr,"swift: HACK checkpointing %s at %lli\n", binmap_filename.c_str(), Complete(td));
	FILE *fp = fopen_utf8(binmap_filename.c_str(),"wb");
	if (!fp) {
		print_error("cannot open mbinmap for writing");
		return -1;
	}
	int ret = ht->serialize(fp);
	if (ret < 0)
		print_error("writing to mbinmap");
	fclose(fp);
	return ret;
}



// SEEK
int swift::Seek(int td, int64_t offset, int whence)
{
	if (api_debug)
		fprintf(stderr,"swift::Seek td %d o %ld w %d\n", td, offset, whence );

	dprintf("%s F%d Seek: to %ld\n",tintstr(), td, offset );
	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm == NULL)
		return -1; // also for LIVE

	// Quick fail in order not to activate a swarm only to fail after activation
	if( whence != SEEK_SET ) // TODO other
		return -1;
	if( offset >= swift::Size(td) )
		return -1;

	if( !swarm->Touch() ) {
		swarm = SwarmManager::GetManager().ActivateSwarm( swarm->RootHash() );
		if (swarm == NULL)
			return -1;
		if (!swarm->Touch())
			return -1;
	}
	FileTransfer *ft = swarm->GetTransfer();

	// whence == SEEK_SET && offset < swift::Size(td)  - validated by quick fail above

	// Which bin to seek to?
	int64_t coff = offset - (offset % ft->hashtree()->chunk_size()); // ceil to chunk
	bin_t offbin = bin_t(0,coff/ft->hashtree()->chunk_size());

	dprintf("%s F%i Seek: to bin %s\n",tintstr(), td, offbin.str().c_str() );

	return ft->picker()->Seek(offbin,whence);
}



void swift::AddPeer(Address& addr, int fd, const Sha1Hash& swarmid)
{
	if (api_debug)
		fprintf(stderr,"swift::AddPeer addr %s hash %s fd %d\n", addr.str().c_str(), swarmid.hex().c_str(), fd );

	ContentTransfer *ct = NULL;
	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(swarmid);
	if (swarm == NULL)
		ct = (ContentTransfer *)LiveTransfer::FindBySwarmID(swarmid);
	else
	{
		if (!swarm->Touch()) {
			swarm = SwarmManager::GetManager().ActivateSwarm(swarmid);
			if (swarm == NULL)
				return;
			if (!swarm->Touch())
				return;
		}
		ct = (ContentTransfer *)swarm->GetTransfer();
	}
	if (ct == NULL)
		return;
	else {
		ct->AddPeer(addr, fd);
	}
	// FIXME: When cached addresses are supported in swapped-out swarms, add the peer to that cache instead
}



/*
 * Progress Monitoring
 */


void swift::AddProgressCallback(int td,ProgressCallback cb,uint8_t agg)
{
	if (api_debug)
		fprintf(stderr,"swift::AddProgressCallback: td %d\n", td);

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return;
		else
			lt->AddProgressCallback(cb,agg);
		return;
	}
	else
		swarm->AddProgressCallback( cb, agg );

	//fprintf(stderr,"swift::AddProgressCallback: swarm obj %p %p\n", swarm, cb );
}



void swift::RemoveProgressCallback(int td, ProgressCallback cb)
{
	if (api_debug)
		fprintf(stderr,"swift::RemoveProgressCallback: td %d\n", td);

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm == NULL)
	{
		LiveTransfer *lt = LiveTransfer::FindByTD(td);
		if (lt == NULL)
			return;
		else
			lt->RemoveProgressCallback(cb);
		return;
	}
	else
		swarm->RemoveProgressCallback(cb);
}


/*
 * Offline hash checking. Writes .mhash and .mbinmap file for the specified
 * content filename.
 *
 * MUST NOT use any swift global variables!
 */

int swift::HashCheckOffline( std::string filename, Sha1Hash *calchashptr, uint32_t chunk_size)
{
	if (api_debug)
		fprintf(stderr,"swift::HashCheckOffline %s hashptr %p cs %u\n", filename.c_str(), calchashptr, chunk_size );

	// From transfer.cpp::FileTransfer constructor
	std::string destdir = dirname_utf8(filename);
	if (destdir == "")
		destdir = ".";

	// MULTIFILE
	Storage *storage_ = new Storage(filename,destdir,-1);

	std::string hash_filename;
	hash_filename.assign(filename);
	hash_filename.append(".mhash");

	std::string binmap_filename;
	binmap_filename.assign(filename);
	binmap_filename.append(".mbinmap");

	MmapHashTree *hashtree_ = new MmapHashTree(storage_,Sha1Hash::ZERO,chunk_size,hash_filename,true,true,binmap_filename);

	FILE *fp = fopen_utf8(binmap_filename.c_str(),"wb");
	if (!fp) {
		print_error("cannot open mbinmap for writing");
		return -1;
	}
	int ret = hashtree_->serialize(fp);
	if (ret < 0)
		print_error("writing to mbinmap");
	fclose(fp);

	*calchashptr = hashtree_->root_hash();

	return ret;
}



/*
 * LIVE
 */


LiveTransfer *swift::LiveCreate(std::string filename, const Sha1Hash& swarmid, uint32_t chunk_size)
{
	if (api_debug)
		fprintf(stderr,"swift::LiveCreate %s hash %s cs %u\n", filename.c_str(), swarmid.hex().c_str(), chunk_size );

	// Arno: LIVE streams are not managed by SwarmManager
	fprintf(stderr,"swift::LiveCreate: swarmid: %s\n",swarmid.hex().c_str() );
	LiveTransfer *lt = new LiveTransfer(filename,swarmid,true,chunk_size);

	if (lt->IsOperational())
		return lt;
	else
	{
		fprintf(stderr,"swift::LiveCreate: %s swarm created, but not operational\n",swarmid.hex().c_str() );
		delete lt;
		return NULL;
	}
}


int swift::LiveWrite(LiveTransfer *lt, const void *buf, size_t nbyte)
{
	//if (api_debug)
	//	fprintf(stderr,"swift::LiveWrite lt %p buf %p n " PRISIZET "\n", lt, buf. nbyte );

	return lt->AddData(buf,nbyte);
}


int swift::LiveOpen(std::string filename, const Sha1Hash& swarmid, Address tracker, bool check_netwvshash, uint32_t chunk_size)
{
	if (api_debug)
		fprintf(stderr,"swift::LiveOpen %s hash %s addr %s cnet %d cs %u\n", filename.c_str(), swarmid.hex().c_str(), tracker.str().c_str(), check_netwvshash, chunk_size );

	LiveTransfer *lt = new LiveTransfer(filename,swarmid,false,chunk_size);

	// initiate tracker connections
	// SWIFTPROC
	lt->SetTracker(tracker);
	lt->ConnectToTracker();
	return lt->td();
}


uint64_t  swift::GetHookinOffset(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::GetHookinOffset td %d\n", td );

	LiveTransfer *lt = LiveTransfer::FindByTD(td);
	if (lt == NULL)
		return 0; // also for FileTransfer
	else
		return lt->GetHookinOffset();
}


// Called from sendrecv.cpp
void swift::Touch(int td)
{
	if (api_debug)
		fprintf(stderr,"swift::Touch: td %d\n", td);

	SwarmData* swarm = SwarmManager::GetManager().FindSwarm(td);
	if (swarm != NULL)
		swarm->Touch();
}
