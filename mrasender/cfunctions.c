/* A C submodule */
#include <tarantool/module.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#define MRA_HOST    						            "mrim.mail.ru"
#define MRA_PORT    						            "2042"
#define VERSION_TXT 						            "tarantool mra sender 1.0.2"
#define MRA_BUF_LEN  						            65536
#define LPSLENGTH(s) 						            (*((uint32_t *)(s)))
#define LPSSIZE(s)   						            (LPSLENGTH(s) + sizeof(uint32_t))
#define LPSALLOC(c)             						((char *) malloc((c) + sizeof(uint32_t)))

#define PROTO_VERSION_MAJOR                 1
#define PROTO_VERSION_MINOR                 8
#define PROTO_VERSION                       ((((u_long)(PROTO_VERSION_MAJOR))<<16)|(u_long)(PROTO_VERSION_MINOR))
#define PROTO_MAJOR(p)                      (((p)&0xFFFF0000)>>16)
#define PROTO_MINOR(p)                      ((p)&0x0000FFFF)
#define CS_MAGIC                            0xDEADBEEF

#define MRIM_CS_HELLO                       0x1001
#define MRIM_CS_HELLO_ACK                   0x1002
#define MRIM_CS_LOGIN_ACK                   0x1004
#define MRIM_CS_LOGIN_REJ                   0x1005
#define MRIM_CS_PING                        0x1006
#define MRIM_CS_MESSAGE                     0x1008
#define MESSAGE_FLAG_OFFLINE                0x00000001
#define MESSAGE_FLAG_NORECV                 0x00000004
#define MESSAGE_FLAG_AUTHORIZE              0x00000008
#define MESSAGE_FLAG_SYSTEM                 0x00000040
#define MESSAGE_FLAG_RTF                    0x00000080
#define MESSAGE_FLAG_CONTACT                0x00000200
#define MESSAGE_FLAG_NOTIFY                 0x00000400
#define MESSAGE_FLAG_MULTICAST              0x00001000
#define MAX_MULTICAST_RECIPIENTS            50
#define MESSAGE_USERFLAGS_MASK              0x000036A8
#define MRIM_CS_MESSAGE_ACK                 0x1009
#define MRIM_CS_MESSAGE_RECV                0x1011
#define MRIM_CS_MESSAGE_STATUS              0x1012
#define MESSAGE_DELIVERED                   0x0000
#define MESSAGE_REJECTED_NOUSER             0x8001
#define MESSAGE_REJECTED_INTERR             0x8003
#define MESSAGE_REJECTED_LIMIT_EXCEEDED     0x8004
#define MESSAGE_REJECTED_TOO_LARGE          0x8005
#define MESSAGE_REJECTED_DENY_OFFMSG        0x8006
#define MRIM_CS_USER_STATUS                 0x100F
#define STATUS_OFFLINE                      0x00000000
#define STATUS_ONLINE                       0x00000001
#define STATUS_AWAY                         0x00000002
#define STATUS_UNDETERMINATED               0x00000003
#define STATUS_FLAG_INVISIBLE               0x80000000
#define MRIM_CS_LOGOUT                      0x1013
#define LOGOUT_NO_RELOGIN_FLAG              0x0010
#define MRIM_CS_CONNECTION_PARAMS           0x1014
#define MRIM_CS_USER_INFO                   0x1015
#define MRIM_CS_ADD_CONTACT                 0x1019
#define CONTACT_FLAG_REMOVED                0x00000001
#define CONTACT_FLAG_GROUP                  0x00000002
#define CONTACT_FLAG_INVISIBLE              0x00000004
#define CONTACT_FLAG_VISIBLE                0x00000008
#define CONTACT_FLAG_IGNORE                 0x00000010
#define CONTACT_FLAG_SHADOW                 0x00000020
#define MRIM_CS_ADD_CONTACT_ACK             0x101A
#define CONTACT_OPER_SUCCESS                0x0000
#define CONTACT_OPER_ERROR                  0x0001
#define CONTACT_OPER_INTERR                 0x0002
#define CONTACT_OPER_NO_SUCH_USER           0x0003
#define CONTACT_OPER_INVALID_INFO           0x0004
#define CONTACT_OPER_USER_EXISTS            0x0005
#define CONTACT_OPER_GROUP_LIMIT            0x0006
#define MRIM_CS_MODIFY_CONTACT              0x101B
#define MRIM_CS_MODIFY_CONTACT_ACK          0x101C
#define MRIM_CS_OFFLINE_MESSAGE_ACK         0x101D
#define MRIM_CS_DELETE_OFFLINE_MESSAGE      0x101E
#define MRIM_CS_AUTHORIZE                   0x1020
#define MRIM_CS_AUTHORIZE_ACK               0x1021
#define MRIM_CS_CHANGE_STATUS               0x1022
#define MRIM_CS_GET_MPOP_SESSION            0x1024
#define MRIM_CS_MPOP_SESSION                0x1025
#define MRIM_GET_SESSION_FAIL               0
#define MRIM_GET_SESSION_SUCCESS            1
#define MRIM_CS_WP_REQUEST                  0x1029
#define PARAMS_NUMBER_LIMIT                 50
#define PARAM_VALUE_LENGTH_LIMIT            64
#define MRIM_CS_ANKETA_INFO                 0x1028
#define MRIM_ANKETA_INFO_STATUS_OK          1
#define MRIM_ANKETA_INFO_STATUS_NOUSER      0
#define MRIM_ANKETA_INFO_STATUS_DBERR       2
#define MRIM_ANKETA_INFO_STATUS_RATELIMERR  3
#define MRIM_CS_MAILBOX_STATUS              0x1033
#define MRIM_CS_CONTACT_LIST2               0x1037
#define GET_CONTACTS_OK                     0x0000
#define GET_CONTACTS_ERROR                  0x0001
#define GET_CONTACTS_INTERR                 0x0002
#define CONTACT_INTFLAG_NOT_AUTHORIZED      0x0001
#define MRIM_CS_LOGIN2                      0x1038
#define MAX_CLIENT_DESCRIPTION              256

enum {
	MRIM_CS_WP_REQUEST_PARAM_USER = 0,
	MRIM_CS_WP_REQUEST_PARAM_DOMAIN,
	MRIM_CS_WP_REQUEST_PARAM_NICKNAME,
	MRIM_CS_WP_REQUEST_PARAM_FIRSTNAME,
	MRIM_CS_WP_REQUEST_PARAM_LASTNAME,
	MRIM_CS_WP_REQUEST_PARAM_SEX,
	MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY,
	MRIM_CS_WP_REQUEST_PARAM_DATE1,
	MRIM_CS_WP_REQUEST_PARAM_DATE2,
	MRIM_CS_WP_REQUEST_PARAM_ONLINE,
	MRIM_CS_WP_REQUEST_PARAM_STATUS,
	MRIM_CS_WP_REQUEST_PARAM_CITY_ID,
	MRIM_CS_WP_REQUEST_PARAM_ZODIAC,
	MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY_MONTH,
	MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY_DAY,
	MRIM_CS_WP_REQUEST_PARAM_COUNTRY_ID,
	MRIM_CS_WP_REQUEST_PARAM_MAX
};

typedef struct mrim_connection_params_t {
	unsigned long	ping_period;
} mrim_connection_params_t;

typedef struct _mrim_packet_header_t {
	uint32_t magic;               // magic
	uint32_t proto;               // protocol version
	uint32_t seq;                 // sequence number
	uint32_t msg;                 // packet type
	uint32_t dlen;                // data length
	uint32_t from;                // sender address
	uint32_t fromport;            // sender port
	u_char   reserved[16];        // reserved
} mrim_packet_header_t;

typedef struct mrasender
{
	int mra_socket;             // mra socket
	char *tx_buf;               // TX buffer
	unsigned int tx_len;        // TX buffer size
	char *rx_buf;               // RX buffer
	unsigned int rx_len;        // RX buffer size
	unsigned int seq;           // Sequence number
	int received_hello_ack;     // Is 'hello' message received
	int received_login_ack;     // Is 'login OK' message recievied
	int received_login_rej;     // Is 'login FAIL' message received
} run_data;

/* mrim connect */
int mrim_connect_tcp(char *host, char *port)
{
	int s;
	struct addrinfo hints, *res;

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1 && errno != EINTR) {
		say_crit("cannot create socket: %s", strerror(errno));
		return -1;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = 0;

	if (getaddrinfo(host, port, &hints, &res) != 0 && errno != EINTR) {
		say_crit("cannot getaddrinfo for %s:%s: %s", host, port, strerror(errno));
		close(s);
		return -1;
	}

	if(connect(s, res->ai_addr, res->ai_addrlen) == -1){
		say_crit("cannot connect to %s:%s: %s", host, port, strerror(errno));
		if (res) {
			freeaddrinfo(res);
		}
		close(s);
		return -1;
	}

	if (res) {
		freeaddrinfo(res);
	}

	return s;
}

/* String -> LPS string */
char *mrim_net_mklps(const char *sz)
{
	uint32_t len;
	char *lps = LPSALLOC(strlen(sz));

	len = strlen(sz);
	*((uint32_t *)lps) = len;
	memcpy(lps + sizeof(uint32_t), sz, strlen(sz));
	return lps;
}

/* LPS string -> String */
char *mrim_net_mksz(char *lps)
{
	uint32_t len;
	char *sz = (char *) malloc(1 + LPSLENGTH(lps));

	len = *((uint32_t *)lps);
	memcpy(sz, lps + sizeof(uint32_t), len);
	*(sz + len) = 0;
	return sz;
}

/* Fill mrim packet header */
void mrim_net_fill_cs_header(mrim_packet_header_t *head, uint32_t seq, uint32_t msg, uint32_t len)
{
	head->proto    = PROTO_VERSION;
	head->magic    = CS_MAGIC;
	head->seq      = seq;
	head->msg      = msg;
	head->dlen     = len;
	head->from     = 0;
	head->fromport = 0;
}

/* Fill RX buffer */
void mrim_net_send(run_data *work_data, void *data, size_t len)
{
	work_data->tx_buf = (char *) realloc(work_data->tx_buf, work_data->tx_len + len);
	memcpy(work_data->tx_buf + work_data->tx_len, data, len);
	work_data->tx_len += len;
}

/* Do send RX buffer */
int mrim_net_send_flush(run_data *work_data)
{
	//tx_len + len

	if (write(work_data->mra_socket, work_data->tx_buf, work_data->tx_len) == -1 && errno != EINTR) {
		say_crit("cannot write data to socket: %s (%d)", strerror(errno), errno);
		return -1;
	} else {
		memset(work_data->tx_buf, 0, sizeof(work_data->tx_buf));
		work_data->tx_len = 0;
		return 0;
	}
}

/* Send 'receive ack' packet */
int mrim_net_send_receive_ack(run_data *work_data, char *from, uint32_t msg_id)
{
	mrim_packet_header_t head;
	char *from_lps = mrim_net_mklps(from);

	memset(&head, 0, sizeof(head));

	mrim_net_fill_cs_header(&head, work_data->seq++, MRIM_CS_MESSAGE_RECV, LPSSIZE(from_lps) + sizeof(msg_id));
	mrim_net_send(work_data, &head, sizeof(head));
	mrim_net_send(work_data, from_lps, LPSSIZE(from_lps));
	mrim_net_send(work_data, &msg_id, sizeof(msg_id));
	free(from_lps);
	
	if (mrim_net_send_flush(work_data) == -1) {
		return -1;
	}
	return 0;
}

/* Send 'auth ack' packet */
int mrim_net_send_auth_request_ack(run_data *work_data, char *email)
{
	mrim_packet_header_t head;
	char *email_lps = mrim_net_mklps(email);

	memset(&head, 0, sizeof(head));

	mrim_net_fill_cs_header(&head, work_data->seq++, MRIM_CS_AUTHORIZE, LPSSIZE(email_lps));
	mrim_net_send(work_data, &head,  sizeof(head));
	mrim_net_send(work_data, email_lps, LPSSIZE(email_lps));
	free(email_lps);
	
	if (mrim_net_send_flush(work_data) == -1) {
		return -1;
	}
	return 0;
}

/* Send 'hello' packet */
int mrim_send_hello(run_data *work_data)
{
	mrim_packet_header_t head;

	memset(&head, 0, sizeof(head));

	mrim_net_fill_cs_header(&head, work_data->seq++, MRIM_CS_HELLO, 0);
	mrim_net_send(work_data, &head, sizeof(head));

	if (mrim_net_send_flush(work_data) == -1) {
		return -1;
	}

	while (work_data->received_hello_ack == 0) {
		if (mrim_net_read(work_data) == -1) {
			return -1;
		}
	}

	return 0;
}

/* Send 'auth' packet*/
int mrim_send_auth(run_data *work_data, const char *username, const char *password, uint32_t status)
{
	mrim_packet_header_t head;
	char *username_lps;
	char *password_lps;
	char *desc_lps;
	uint32_t dw = 0;
	size_t i;

	memset(&head, 0, sizeof(head));

	// convert username, password and desc to LPS
	username_lps = mrim_net_mklps(username);
	password_lps = mrim_net_mklps(password);
	desc_lps     = mrim_net_mklps(VERSION_TXT);

	// send all data
	mrim_net_fill_cs_header(&head, work_data->seq++, MRIM_CS_LOGIN2, LPSSIZE(username_lps) + LPSSIZE(password_lps) + LPSSIZE(desc_lps) + sizeof(uint32_t) * 6);
	mrim_net_send(work_data, &head, sizeof(head));
	mrim_net_send(work_data, username_lps, LPSSIZE(username_lps));
	mrim_net_send(work_data, password_lps, LPSSIZE(password_lps));
	mrim_net_send(work_data, &status, sizeof(status));
	mrim_net_send(work_data, desc_lps, LPSSIZE(desc_lps));

	for (i = 0; i < 5; i++) {
		mrim_net_send(work_data, &dw, sizeof(dw));
	}

	free(username_lps);
	free(password_lps);
	free(desc_lps);

	if (mrim_net_send_flush(work_data) == -1) {
		return -1;
	}

	while (work_data->received_login_ack == 0 && work_data->received_login_rej == 0) {
		if (mrim_net_read(work_data) == -1) {
			return -1;
		}
	}

	return 0;
}

/* Send 'message' packet */
int mrim_send_message(run_data *work_data, const char *to, const char *message, uint32_t flags)
{
	mrim_packet_header_t head;
	char *to_lps;
	char *message_lps;
	char *message_rtf_lps;
	int ret;

	memset(&head, 0, sizeof(head));

	to_lps = mrim_net_mklps(to);
	message_lps = mrim_net_mklps(message);
	message_rtf_lps = mrim_net_mklps(" ");

	mrim_net_fill_cs_header(&head, work_data->seq++, MRIM_CS_MESSAGE, sizeof(uint32_t) + LPSSIZE(to_lps) + LPSSIZE(message_lps) + LPSSIZE(message_rtf_lps));
	mrim_net_send(work_data, &head,  sizeof(head));
	mrim_net_send(work_data, &flags, sizeof(uint32_t));
	mrim_net_send(work_data, to_lps, LPSSIZE(to_lps));
	mrim_net_send(work_data, message_lps, LPSSIZE(message_lps));
	mrim_net_send(work_data, message_rtf_lps, LPSSIZE(message_rtf_lps));
	ret = mrim_net_send_flush(work_data);

	free(to_lps);
	free(message_lps);
	free(message_rtf_lps);

	return ret;
}

/* Send 'ping' packet */
int mrim_send_ping(run_data *work_data)
{
	mrim_packet_header_t head;
	memset(&head, 0, sizeof(head));
	
	say_crit("Send 'PING' packet");

	mrim_net_fill_cs_header(&head, work_data->seq++, MRIM_CS_PING, 0);
	mrim_net_send(work_data, &head, sizeof(head));
	return mrim_net_send_flush(work_data);
}

/* Read incoming 'message' packet */
void mrim_read_message(run_data *work_data, char *answer, uint32_t len)
{
	uint32_t msg_id;
	uint32_t flags;
	char *from;

	// parse data
	msg_id = *(uint32_t *) answer;
	answer += sizeof(uint32_t);
	flags = *(uint32_t *) answer;
	answer += sizeof(uint32_t);
	from = mrim_net_mksz(answer);

	// send receive ack if needed
	if (!(flags & MESSAGE_FLAG_NORECV)) {
		mrim_net_send_receive_ack(work_data, from, msg_id);
	}

	// proceed message
	if (flags & MESSAGE_FLAG_AUTHORIZE) {
		// authorization request
		mrim_net_send_auth_request_ack(work_data, from);
//	} else if (flags & MESSAGE_FLAG_SYSTEM) {
//		// system message
//	} else if (flags & MESSAGE_FLAG_CONTACT) {
//		// contacts list
//	} else if (flags & MESSAGE_FLAG_NOTIFY) {
//		// typing notify
//	} else {
//		// casual message
	}

	free(from);
}

/*	Read and parce incoming message */
int mrim_net_read_proceed(run_data *work_data)
{
	mrim_packet_header_t *head;
	size_t packet_len = 0;
	char *answer;
	char *next_packet;
	char *ddata = NULL;

	memset(&head, 0, sizeof(head));

	if (work_data->rx_len == 0) {
		return 0;
	}

	if (work_data->rx_len < sizeof(mrim_packet_header_t)) {
		return 0;
	}

	// detach MRIM packet header from readed data
	head = (mrim_packet_header_t *) work_data->rx_buf;

	// check if we have correct magic
	if (head->magic != CS_MAGIC) {
		say_crit("mrim_net_read_proceed: wrong magic: 0x%08x", (uint32_t) head->magic);
		return -1;
	}

	packet_len = sizeof(mrim_packet_header_t) + head->dlen;


	// check if we received full packet
	if (work_data->rx_len < packet_len) {
		return 0;
	}

	// get answer value
	answer = work_data->rx_buf + sizeof(mrim_packet_header_t);

	// proceed packet
	switch(head->msg) {
		case MRIM_CS_HELLO_ACK:
			// 'hello' packet
			say_crit("received 'MRIM_CS_HELLO_ACK' packet");
			work_data->received_hello_ack = 1;
			break;
		case MRIM_CS_LOGIN_ACK:
			// 'login successful' packet
			say_crit("received 'MRIM_CS_LOGIN_ACK' packet");
			work_data->received_login_ack = 1;
			break;
		case MRIM_CS_LOGIN_REJ:
			// 'login failed' packet
			say_crit("received 'MRIM_CS_LOGIN_REJ' packet");
			work_data->received_login_rej = 1;
			break;
		case MRIM_CS_MESSAGE_ACK:
			// 'receive message' packet
			say_crit("received 'MRIM_CS_MESSAGE_ACK' packet");
			mrim_read_message(work_data, answer, head->dlen);
			break;
		case MRIM_CS_USER_INFO:
			// 'user info' packet
			say_crit("received 'MRIM_CS_USER_INFO' packet");
			break;
		case MRIM_CS_MESSAGE_STATUS:
			// 'message status' packet
			say_crit("received 'MRIM_CS_MESSAGE_STATUS' packet");
			break;
		case MRIM_CS_CONTACT_LIST2:
			// 'contact list' packet
			say_crit("received 'MRIM_CS_CONTACT_LIST2' packet");
			break;
		default:
			// unknown packet
			say_crit("unknown packet received: 0x%04x", head->msg);
	}

	// if we have more data in incoming buffer
	if (work_data->rx_len > packet_len) {
		// cut proceeded packet
		next_packet = work_data->rx_buf + packet_len;
		work_data->rx_len = work_data->rx_len - packet_len;
		memmove(work_data->rx_buf, next_packet, work_data->rx_len);
		work_data->rx_buf = realloc(work_data->rx_buf, work_data->rx_len);
		return 0;
	} else {
		// else just empty buffer
		work_data->rx_len = 0;
		work_data->rx_buf = realloc(work_data->rx_buf, MRA_BUF_LEN + 1);
	}
	return 1;
}

/* Read data from mail.ru agent server */
int mrim_net_read(run_data *work_data)
{
	int len;
	char *buf;
	int net_read_try_count = 0;
	int res = 0;

	// increase buffer size
	work_data->rx_buf = realloc(work_data->rx_buf, work_data->rx_len + MRA_BUF_LEN + 1);

	// read data from socket
	buf = work_data->rx_buf + work_data->rx_len;
	len = read(work_data->mra_socket, buf, MRA_BUF_LEN);
	work_data->rx_len = work_data->rx_len + len;

	if (len < 0 && errno == EAGAIN && errno != EINTR) {
		// read more
		return 0;
	} else if (len < 0) {
		say_crit("cannot read data from socket: %s", strerror(errno));
		return -1;
	} else if (len == 0) {
		// server closed the connection
		say_crit("server closed the connection: %s", strerror(errno));
		return -1;
	}

	// proceed received data while we can do it =)
	while (res == 0) {
		res = mrim_net_read_proceed(work_data);

		if (res == 0) {
			net_read_try_count++;
		}

		if (net_read_try_count > 300) {
			break;
		}

	}
	return 0;
}

/* Check if data exists */
int mrim_is_readable(run_data *work_data, int timeout_sec, int timeout_usec)
{
	struct timeval tv;
	fd_set rset;
	int isready;

	FD_ZERO(&rset);
	FD_SET(work_data->mra_socket, &rset);

	tv.tv_sec  = timeout_sec;
	tv.tv_usec = timeout_usec;

again:
	isready = select(work_data->mra_socket + 1, &rset, NULL, NULL, &tv);
	if (isready < 0) {
		if (errno == EINTR) goto again;
		say_crit("error on select socket: %s", strerror(errno));
		return -1;
	}

	return isready;
}

/*	split "host:port" to "host" and "port" */
static void split_host_port(char *login_data, int login_data_size, char *host, int host_size, char *port, int port_size)
{
	char *delim_pos = memchr(login_data, ':', login_data_size);

	memset(host, 0, host_size);
	memset(port, 0, port_size);

	if (delim_pos){
		*delim_pos='\0';
		strncpy(host, login_data, host_size-1);
		strncpy(port, delim_pos+1, port_size-1);
	}
}

/*	Connect and login */
int mrim_connect(run_data *work_data, char *login_host, char *login_port, char *username, char *password)
{
	int login_data_size = -1;
	char login_data[24];
	char host[16];
	char port[5];

	say_crit("Start connect to server %s:%s, username: %s, password: %s", login_host, login_port, "***", "***");

	work_data->received_hello_ack = 0;
	work_data->received_login_ack = 0;
	work_data->received_login_rej = 0;

	if (work_data->mra_socket > 0) {
		close(work_data->mra_socket);
	}
	// let's get server to connect to
	if ((work_data->mra_socket = mrim_connect_tcp(login_host, login_port)) == -1) {
		say_crit("cannot connect to %s:%s", login_host, login_port);
		return -1;
	}

	if ((login_data_size = read(work_data->mra_socket, login_data, sizeof(login_data))) == -1 && errno != EINTR) {
		say_crit("cannot read data from socket: %s", strerror(errno));
		return -1;
	}

	if ((work_data->mra_socket = close(work_data->mra_socket)) == -1 && errno != EINTR) {
		say_crit("cannot close socket: %s", strerror(errno));
		return -1;
	}

	
	split_host_port(login_data, login_data_size, host, sizeof(host), port, sizeof(port));
	say_crit("Login host: %s", host);
	say_crit("Login port: %s", port);

	// let's connect to mrim server
	if ((work_data->mra_socket = mrim_connect_tcp(host, port)) == -1) {
		say_crit("cannot connect to %s:%s", host, port);
		return -1;
	}

	// send 'hello' packet
	if (mrim_send_hello(work_data) == -1) {
		say_crit("cannot send 'hello' packet");
		return -1;
	}

	// send 'login' packet
	if (mrim_send_auth(work_data, username, password, STATUS_ONLINE) == -1) {
		say_crit("cannot send 'login' packet");
		return -1;
	}

	if (work_data->received_login_rej == 1) {
		say_crit("cannot auth: username or password is wrong");
		return -1;
	}

	return 0;
}

/* Disconnect */
int mrim_disconnect(run_data *work_data)
{
	if (work_data->mra_socket) {
		shutdown(work_data->mra_socket, 1); 
		close(work_data->mra_socket);
	}
	return 0;
}

/* login, send message, disconnect */
int send_mra_message(const char *username, const char *password, const char *recipient, const char *msg)
{
	int err = 0;

	char username_in[255];          // username
	char password_in[255];          // recipient
	char recipient_in[255];         // recipient
	char msg_in[1024*1024];         // msg

	run_data work_data;
	memset(&work_data, 0, sizeof(work_data));

	work_data.mra_socket = -1;            // mra socket
	work_data.tx_buf = NULL;              // TX buffer
	work_data.tx_len = 0;                 // TX buffer size
	work_data.rx_buf = NULL;              // RX buffer
	work_data.rx_len = 0;                 // RX buffer size
	work_data.seq = 0;                    // Sequence number
	work_data.received_hello_ack = 0;     // Is 'hello' message received
	work_data.received_login_ack = 0;     // Is 'login OK' message recievied
	work_data.received_login_rej = 0;     // Is 'login FAIL' message received

	// assign username
	if (username) {
		snprintf(username_in, sizeof(username_in)-1, "%s", username);
	} else {
		return -2;
	}

	// assign password
	if (password) {
		snprintf(password_in, sizeof(password_in)-1, "%s", password);
	} else {
		return -3;
	}

	// assign recipient
	if (recipient) {
		snprintf(recipient_in, sizeof(recipient_in)-1, "%s", recipient);
	}

	if (!recipient_in) {
		snprintf(recipient_in, sizeof(recipient_in)-1, "%s", username);
	}

	if (msg) {
		snprintf(msg_in, sizeof(msg_in)-1, "%s", msg);
	}

	if (!msg_in) {
		snprintf(msg_in, sizeof(msg_in)-1, "%s", "ERROR! No params recipient and msg body!");
	}

	// Connect to mail.ru agent if not connected yet
	if (mrim_connect(&work_data, MRA_HOST, MRA_PORT, username_in, password_in) == -1) {
		say_crit("%s", "Can't connect to mail.ru agent");
		mrim_disconnect(&work_data);
		return -1;
	}

	if (mrim_is_readable(&work_data, 0, 500)) {
		if(mrim_net_read(&work_data) == -1) {
			mrim_disconnect(&work_data);
			mrim_connect(&work_data, MRA_HOST, MRA_PORT, username_in, password_in);
		}
	}

	err = mrim_send_message(&work_data, recipient_in, msg_in, 0);
	if(err == -1){
		say_crit("cannot send message to '%s'", recipient);
		mrim_disconnect(&work_data);
		if (work_data.rx_buf) free(work_data.rx_buf);
		if (work_data.tx_buf) free(work_data.tx_buf);
		return -4;
	}

	fiber_sleep(1);
	mrim_disconnect(&work_data);

	if (work_data.rx_buf) free(work_data.rx_buf);
	if (work_data.tx_buf) free(work_data.tx_buf);

	return 0;
}

/**
 * Start send message
 */
static int mrasender_func(struct lua_State *L)
{
	if (lua_gettop(L) < 4)
		luaL_error(L, "Usage: cfunctions.send(username: string, password: string, recipient: string, msg: string)");

	const char *username  = lua_tostring(L, 1);
	const char *password  = lua_tostring(L, 2);
	const char *recipient = lua_tostring(L, 3);
	const char *msg       = lua_tostring(L, 4);

	lua_pushinteger(L, send_mra_message(username, password, recipient, msg));
	return 1;
}

LUA_API int luaopen_mrasender_cfunctions(lua_State *L)
{
	/* result is returned from require('mrasender.cfunctions') */
	lua_newtable(L);
	static const struct luaL_reg meta [] = {
		{"send_message_to_mra", mrasender_func},
		{NULL, NULL}
	};
	luaL_register(L, NULL, meta);
	return 1;
}
