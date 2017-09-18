/*
 * Copyright (c) 2008, The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of Google, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/netlink.h>

#define MAX_EPOLL_EVENTS	40
#define MAX_UEVENT_ITEMS	64
#define NAME_LEN                32

#define POWER_SUPPLY            "power_supply"

static int eventct;
static int epollfd;
static int uevent_fd;

struct uevent {
        const char *action;
        const char *path;
        const char *subsystem;
        const char *firmware;
	const char *item[MAX_UEVENT_ITEMS];
	int major;
	int minor;
	int seqnum;
	int item_count;
};

struct virtio_uevent {
        uint8_t         action;/* refers to kobject_action */
        char            path[NAME_LEN];/* refers to the path of uevent */
};

typedef struct virtio_uevent virtio_uevent;

enum kobject_action {
        KOBJ_ADD,
        KOBJ_REMOVE,
        KOBJ_CHANGE,
        KOBJ_MOVE,
        KOBJ_ONLINE,
        KOBJ_OFFLINE,
        KOBJ_MAX
};

/* the strings here must match the enum in include/linux/kobject.h */
static const char *kobject_actions[] = {
        [KOBJ_ADD] =            "add",
        [KOBJ_REMOVE] =         "remove",
        [KOBJ_CHANGE] =         "change",
        [KOBJ_MOVE] =           "move",
        [KOBJ_ONLINE] =         "online",
        [KOBJ_OFFLINE] =        "offline",
};

static int find_kobject_action(const char *action) {
        int i = 0;
        while (i < KOBJ_MAX) {
            if (strncmp(action, kobject_actions[i],\
                        strlen(kobject_actions[i])) == 0) {
                break;
            }
            i++;
        }
        return i;
}

static int open_uevent_socket(void)
{
        struct sockaddr_nl addr;
        int sz = 64*1024; // XXX larger? udev uses
        int on = 1;
        int s;
        memset(&addr, 0, sizeof(addr));
        addr.nl_family = AF_NETLINK;
        addr.nl_pid = getpid();
        addr.nl_groups = 0xffffffff;
        s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
        if(s < 0)
            return -1;
        setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz));
        setsockopt(s, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
        if(bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            close(s);
            return -1;
        }
        return s;
}

static void parse_event(const char *msg, struct uevent *uevent)
{
	int i = 0;
        char *tmp;

        virtio_uevent event;
        memset(&event, 0, sizeof(event));

        uevent->action = "";
        uevent->path = "";
        uevent->subsystem = "";
        uevent->firmware = "";
        uevent->major = -1;
        uevent->minor = -1;
	uevent->item_count = 0;

	for (; i < MAX_UEVENT_ITEMS; i++)
	    uevent->item[i] = "";

	i = 0;
        while(*msg) {
            if(!strncmp(msg, "ACTION=", 7)) {
                msg += 7;
                uevent->action = msg;
            } else if(!strncmp(msg, "DEVPATH=", 8)) {
                msg += 8;
                uevent->path = msg;
            } else if(!strncmp(msg, "SUBSYSTEM=", 10)) {
                msg += 10;
                uevent->subsystem = msg;
            } else if(!strncmp(msg, "FIRMWARE=", 9)) {
                msg += 9;
                uevent->firmware = msg;
            } else if(!strncmp(msg, "MAJOR=", 6)) {
                msg += 6;
                uevent->major = atoi(msg);
            } else if(!strncmp(msg, "MINOR=", 6)) {
                msg += 6;
                uevent->minor = atoi(msg);
            } else if(!strncmp(msg, "SEQNUM=", 7)) {
		msg += 7;
		uevent->seqnum = atoi(msg);
	    } else {
		uevent->item[i++] = msg;
	    }
	    msg += strlen(msg) + 1;
	}
	uevent->item_count = i;

        printf("\nevent { '%s', '%s', '%s', '%s', %d, %d, %d}\n\n",
                        uevent->action, uevent->path, uevent->subsystem,
                        uevent->firmware, uevent->major, uevent->minor,
			uevent->seqnum);

	for (i=0; i < uevent->item_count; i++)
	    printf("event item[%02d]: %s\n", i, uevent->item[i]);

        if (strncmp(uevent->subsystem, \
                    POWER_SUPPLY, strlen(POWER_SUPPLY)) == 0) {
            tmp = strstr(uevent->path, POWER_SUPPLY);
            tmp += strlen(POWER_SUPPLY) + 1;
            printf("power supply name: %s\n", tmp);

            event.action = find_kobject_action(uevent->action);
            strncpy(event.path, tmp, strlen(tmp));
            printf("event action: %d, path: %s\n", event.action, event.path);
        }
}

#define UEVENT_MSG_LEN 2048

void handle_device_fd(uint32_t epevents)
{
        printf("enter %s\n", __func__);
	{
            char msg[UEVENT_MSG_LEN+2];
            char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
            struct iovec iov = {msg, sizeof(msg)};
            struct sockaddr_nl snl;
            struct msghdr hdr = {&snl, sizeof(snl), &iov, 1, cred_msg, sizeof(cred_msg), 0};
            printf("%s %d\n", __FUNCTION__, __LINE__);
            ssize_t n = recvmsg(uevent_fd, &hdr, 0);
            if (n <= 0) {
                printf("break\n");
                return;
            }
            if ((snl.nl_groups != 1) || (snl.nl_pid != 0)) {
                /* ignoring non-kernel netlink multicast message */
                printf("ignore non-kernel\n");
                return;
            }
            struct cmsghdr * cmsg = CMSG_FIRSTHDR(&hdr);
            if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
                /* no sender credentials received, ignore message */
                printf("no sender credentials\n");
                return;
            }
            struct ucred * cred = (struct ucred *)CMSG_DATA(cmsg);
            if (cred->uid != 0) {
                /* message from non-root user, ignore */
                printf("ingore non-root user\n");
                return;
            }
            if(n >= UEVENT_MSG_LEN) {
                /* overflow -- discard */
                printf("overflow\n");
                return;
            }
            msg[n] = '\0';
            msg[n+1] = '\0';
            struct uevent uevent;
            parse_event(msg, &uevent);
        }
}

int register_event(int fd, void (*handler)(uint32_t)) {
	struct epoll_event ev;

	ev.events = EPOLLIN | EPOLLWAKEUP;
	ev.data.ptr = (void *)handler;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
	    printf("epoll_ctl failed; errno=%d\n", errno);
	    return -1;
	}

	eventct++;
	return 0;
}

static void mainloop(void) {
	while (1) {
	    struct epoll_event events[eventct];
	    int nevents;
	    int n;
	    nevents = epoll_wait(epollfd, events, eventct, -1);

	    if (nevents == -1) {
		if (errno == EINTR)
		    continue;
		printf("healthd_mainloop: epoll_wait failed\n");
		break;
	    }

	    for (n = 0; n < nevents; ++n) {
		if (events[n].data.ptr)
		    (*(void (*)(int))events[n].data.ptr)(events[n].events);
	    }
	}

	return;
}

int cue_main(int argc, char *argv[])
{
	/* now we don't know how to use the input parameters for uevent */
	/* leave it here, FIX IT */
	epollfd = epoll_create(MAX_EPOLL_EVENTS);
	if (epollfd == -1) {
            printf("epoll_create failed; errno=%d\n",
                   errno);
	    return -1;
	}

        uevent_fd = open_uevent_socket();
        if (uevent_fd < 0) {
            printf("error!\n");
            return -1;
        }

	fcntl(uevent_fd, F_SETFL, O_NONBLOCK);

	register_event(uevent_fd, handle_device_fd);

	mainloop();

	return 0;
}
