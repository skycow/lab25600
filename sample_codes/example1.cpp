#include "frameio.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <queue>

frameio net;             // gives us access to the raw network
message_queue ip_queue;  // message queue for the IP protocol stack
message_queue arp_queue; // message queue for the ARP protocol stack

struct ether_frame       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
   octet data[1500];     // payload
};

struct arp_payload
{
   octet hardwaretype[2];
   octet protocoltype[2];
   octet hal;
   octet pal;
   octet opcode[2];
   octet sha[6];
   octet sip[4];
   octet tha[6];
   octet tip[4];

};

struct cache_info
{
   octet ip[4];
   octet mac[6];

};

std::queue<cache_info> cache;

//
// This thread sits around and receives frames from the network.
// When it gets one, it dispatches it to the proper protocol stack.
//
void *protocol_loop(void *arg)
{
   ether_frame buf;
   while(1)
   {
      int n = net.recv_frame(&buf,sizeof(buf));
      if ( n < 42 ) continue; // bad frame!
      switch ( buf.prot[0]<<8 | buf.prot[1] )
      {
          case 0x800:
             ip_queue.send(PACKET,buf.data,n);
             break;
          case 0x806:
             arp_queue.send(PACKET,&buf,n);
             break;
      }
   }
}

//
// Toy function to print something interesting when an IP frame arrives
//
void *ip_protocol_loop(void *arg)
{
   octet buf[1500];
   event_kind event;
   int timer_no = 1;
   cache_info temp;

   // for fun, fire a timer each time we get a frame
   while ( 1 )
   {
      ip_queue.recv(&event, buf, sizeof(buf));
      if ( event != TIMER )
      {
         //printf("got an IP frame from %d.%d.%d.%d, queued timer %d\n",
                  //buf[12],buf[13],buf[14],buf[15],timer_no);
         //temp = buf[12];
         //printf("test: %d\n",temp.ip[1]);
         ip_queue.timer(10,timer_no);
         timer_no++;
      }
      else
      {
         //printf("timer %d fired\n",*(int *)buf);
      }
   }
}

//
// Toy function to print something interesting when an ARP frame arrives
//
void *arp_protocol_loop(void *arg)
{
   ether_frame buf;
   event_kind event;
   cache_info temp;
   ether_frame sending;
   arp_payload tosend;

   while ( 1 )
   {
      arp_queue.recv(&event, &buf, sizeof(buf));
      if(buf.data[7] == 1){

      for(int i =0; i<sizeof(buf.src_mac); i++){
        sending.dst_mac[i] = buf.src_mac[i];
      }
      for(int i =0; i<sizeof(net.get_mac()); i++){
        sending.src_mac[i] = net.get_mac()[i];
      }
      for(int i =0; i<sizeof(buf.prot); i++){
        sending.prot[i] = buf.prot[i];
      }

      tosend.hardwaretype[0] = 0x00;
      tosend.hardwaretype[1] = 0x01;
      tosend.protocoltype[0] = 0x08;
      tosend.protocoltype[1] = 0x00;
      tosend.hal = 0x6;
      tosend.pal = 0x4;
      tosend.opcode[0] = 0x0;
      tosend.opcode[1] = 0x2;
    
      for(int i =0; i<sizeof(net.get_mac()); i++){
        tosend.sha[i] = net.get_mac()[i];
      }

      tosend.sip[0] = 192;
      tosend.sip[1] = 168;
      tosend.sip[2] = 1;
      tosend.sip[3] = 40;

      for(int i =0; i<sizeof(buf.src_mac); i++){
        tosend.tha[i] = buf.src_mac[i];
      }
      
      for(int i = 0; i< 4; i++)
      {
        tosend.tip[i] = buf.data[14+i];
      }

      memcpy(&sending.data[0], &tosend, 28);

      //for(int i = 0; i < 26; i++)
      //{
      //  sending.data[14+i] = tosend[i];
      //}

      for(int i = 0; i < 18; i++)
      {
        sending.data[42+i] = 0;
      }

      for(int i = 0; i < 4; i++)
      {
        sending.data[60+i] = 0;
      }  

      int flag = 0;

      for(int i = 0; i < 4; i++)
      {
        flag += (buf.data[24+i] - tosend.sip[i]);
        printf("%x - %x\n",buf.data[24+i],tosend.sip[i]);
      }    

      if(flag == 0){
        int n = net.send_frame(&sending, 42);
        printf("sent\n");
      }

      //printf("%x.%x.%x.%x.%x.%x",net.get_mac()[0],net.get_mac()[1],net.get_mac()[2],net.get_mac()[3],net.get_mac()[4],net.get_mac()[5]);

      //sending.data = buf;

      //int n = net.send_frame(&buf,sizeof(buf));

      //cache.push(temp);
      printf("pushed\n");
      }
      //printf("got an ARP %s\n", buf[7]==1? "request":"reply");
   }
}

//
// if you're going to have pthreads, you'll need some thread descriptors
//
pthread_t loop_thread, arp_thread, ip_thread;

//
// start all the threads then step back and watch (actually, the timer
// thread will be started later, but that is invisible to us.)
//
int main()
{
   net.open_net("enp3s0");
   pthread_create(&loop_thread,NULL,protocol_loop,NULL);
   pthread_create(&arp_thread,NULL,arp_protocol_loop,NULL);
   pthread_create(&ip_thread,NULL,ip_protocol_loop,NULL);
   for ( ; ; )
      sleep(1);
}

