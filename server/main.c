#include <stdlib.h>

#include <ulfius.h>

#include "../logger.h"

#define DEFAULT_PORT 9000

/* Add client to queue */
// void
// queue_add(client_t *cl)
// {
//     pthread_mutex_lock(&clients_mutex);
//     for (int i = 0; i < MAX_CLIENTS; ++i) {
//         if (!clients[i]) {
//             clients[i] = cl;
//             break;
//         }
//     }
//     pthread_mutex_unlock(&clients_mutex);
// }

// /* Delete client from queue */
// void
// queue_delete(int uid)
// {
//     pthread_mutex_lock(&clients_mutex);
//     for (int i = 0; i < MAX_CLIENTS; ++i) {
//         if (clients[i]) {
//             if (clients[i]->uid == uid) {
//                 clients[i] = NULL;
//                 break;
//             }
//         }
//     }
//     pthread_mutex_unlock(&clients_mutex);
// }

#if defined(U_DISABLE_WEBSOCKET)
int
main()
{
    fprintf(stderr, "error: websocket not supported. please recompile ulfius with websocket support\n");
    return 1;
}
#else

int callback_websocket (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_websocket_echo (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_websocket_file (const struct _u_request * request, struct _u_response * response, void * user_data);

void websocket_onclose_file_callback (const struct _u_request * request,
                                struct _websocket_manager * websocket_manager,
                                void * websocket_onclose_user_data) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "websocket_onclose_file_callback");
}

/**
 * websocket_onclose_callback
 * onclose callback function
 * Used to clear data after the websocket connection is closed
 */
void websocket_onclose_callback (const struct _u_request * request,
                                struct _websocket_manager * websocket_manager,
                                void * websocket_onclose_user_data) {
  if (websocket_onclose_user_data != NULL) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "websocket_onclose_user_data is %s", websocket_onclose_user_data);
    o_free(websocket_onclose_user_data);
  }
}

void websocket_echo_message_callback (const struct _u_request * request,
                                         struct _websocket_manager * websocket_manager,
                                         const struct _websocket_message * last_message,
                                         void * websocket_incoming_message_user_data) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "Incoming message, rsv: 0x%02x, opcode: 0x%02x, mask: %d, len: %zu, text payload '%.*s'", last_message->rsv, last_message->opcode, last_message->has_mask, last_message->data_len, last_message->data_len, last_message->data);
  if (ulfius_websocket_send_message(websocket_manager, last_message->opcode, last_message->data_len, last_message->data) != U_OK) {
    //y_log_message(Y_LOG_LEVEL_ERROR, "Error ulfius_websocket_send_message");
  }
}

/**
 * websocket_manager_callback
 * send 5 text messages and 1 ping for 11 seconds, then closes the websocket
 */
void
websocket_manager_callback(const struct _u_request * request,
                               struct _websocket_manager * websocket_manager,
                               void * websocket_manager_user_data) {
  if (websocket_manager_user_data != NULL) {
    //y_log_message(Y_LOG_LEVEL_DEBUG, "websocket_manager_user_data is %s", websocket_manager_user_data);
  }
  
  // Send text message without fragmentation
  if (ulfius_websocket_wait_close(websocket_manager, 2000) == U_WEBSOCKET_STATUS_OPEN) {
    if (ulfius_websocket_send_message(websocket_manager, U_WEBSOCKET_OPCODE_TEXT, o_strlen("Message without fragmentation from server"), "Message without fragmentation from server") != U_OK) {
      //y_log_message(Y_LOG_LEVEL_ERROR, "Error send message without fragmentation");
    }
  }
  
  // Send text message with fragmentation for ulfius clients only, browsers seem to dislike fragmented messages
  if (o_strncmp(u_map_get(request->map_header, "User-Agent"), U_WEBSOCKET_USER_AGENT, o_strlen(U_WEBSOCKET_USER_AGENT)) == 0 &&
      ulfius_websocket_wait_close(websocket_manager, 2000) == U_WEBSOCKET_STATUS_OPEN) {
    if (ulfius_websocket_send_fragmented_message(websocket_manager, U_WEBSOCKET_OPCODE_TEXT, o_strlen("Message with fragmentation from server"), "Message with fragmentation from server", 5) != U_OK) {
      //y_log_message(Y_LOG_LEVEL_ERROR, "Error send message with fragmentation");
    }
  }
  
  // Send ping message
  if (ulfius_websocket_wait_close(websocket_manager, 2000) == U_WEBSOCKET_STATUS_OPEN) {
    if (ulfius_websocket_send_message(websocket_manager, U_WEBSOCKET_OPCODE_PING, 0, NULL) != U_OK) {
      //y_log_message(Y_LOG_LEVEL_ERROR, "Error send ping message");
    }
  }
  
  // Send binary message without fragmentation
  if (ulfius_websocket_wait_close(websocket_manager, 2000) == U_WEBSOCKET_STATUS_OPEN) {
    if (ulfius_websocket_send_message(websocket_manager, U_WEBSOCKET_OPCODE_BINARY, o_strlen("Message without fragmentation from server"), "Message without fragmentation from server") != U_OK) {
      //y_log_message(Y_LOG_LEVEL_ERROR, "Error send binary message without fragmentation");
    }
  }
  
  // Send JSON message without fragmentation
#ifndef U_DISABLE_JANSSON
  if (ulfius_websocket_wait_close(websocket_manager, 2000) == U_WEBSOCKET_STATUS_OPEN) {
    json_t * message = json_pack("{ss}", "send", "JSON message without fragmentation");
    if (ulfius_websocket_send_json_message(websocket_manager, message) != U_OK) {
      //y_log_message(Y_LOG_LEVEL_ERROR, "Error send JSON message without fragmentation");
    }
    json_decref(message);
  }
#endif

  //y_log_message(Y_LOG_LEVEL_DEBUG, "Closing websocket_manager_callback");
}

/**
 * websocket_incoming_message_callback
 * Read incoming message and prints it on the console
 */
void websocket_incoming_message_callback (const struct _u_request * request,
                                         struct _websocket_manager * websocket_manager,
                                         const struct _websocket_message * last_message,
                                         void * websocket_incoming_message_user_data) {
  if (websocket_incoming_message_user_data != NULL) {
    //y_log_message(Y_LOG_LEVEL_DEBUG, "websocket_incoming_message_user_data is %s", websocket_incoming_message_user_data);
  }
  //y_log_message(Y_LOG_LEVEL_DEBUG, "Incoming message, rsv: 0x%02x, opcode: 0x%02x, mask: %d, len: %zu", last_message->rsv, last_message->opcode, last_message->has_mask, last_message->data_len);
  if (last_message->opcode == U_WEBSOCKET_OPCODE_TEXT) {
    //y_log_message(Y_LOG_LEVEL_DEBUG, "text payload '%.*s'", last_message->data_len, last_message->data);
  } else if (last_message->opcode == U_WEBSOCKET_OPCODE_BINARY) {
    //y_log_message(Y_LOG_LEVEL_DEBUG, "binary payload");
  }
}

void websocket_manager_file_callback(const struct _u_request * request,
                               struct _websocket_manager * websocket_manager,
                               void * websocket_manager_user_data) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "Opening websocket_manager_file_callback");
  for (;;) {
    sleep(1);
    if (websocket_manager == NULL || !websocket_manager->connected) {
      break;
    }
  }
  y_log_message(Y_LOG_LEVEL_DEBUG, "Closing websocket_manager_file_callback");
}

/**
 * websocket_incoming_message_callback
 * Read incoming message and prints it on the console
 */
void websocket_incoming_message_callback (const struct _u_request * request,
                                         struct _websocket_manager * websocket_manager,
                                         const struct _websocket_message * last_message,
                                         void * websocket_incoming_message_user_data) {
  if (websocket_incoming_message_user_data != NULL) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "websocket_incoming_message_user_data is %s", websocket_incoming_message_user_data);
  }
  y_log_message(Y_LOG_LEVEL_DEBUG, "Incoming message, rsv: 0x%02x, opcode: 0x%02x, mask: %d, len: %zu", last_message->rsv, last_message->opcode, last_message->has_mask, last_message->data_len);
  if (last_message->opcode == U_WEBSOCKET_OPCODE_TEXT) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "text payload '%.*s'", last_message->data_len, last_message->data);
  } else if (last_message->opcode == U_WEBSOCKET_OPCODE_BINARY) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "binary payload");
  }
}

void websocket_echo_message_callback (const struct _u_request * request,
                                         struct _websocket_manager * websocket_manager,
                                         const struct _websocket_message * last_message,
                                         void * websocket_incoming_message_user_data) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "Incoming message, rsv: 0x%02x, opcode: 0x%02x, mask: %d, len: %zu, text payload '%.*s'", last_message->rsv, last_message->opcode, last_message->has_mask, last_message->data_len, last_message->data_len, last_message->data);
  if (ulfius_websocket_send_message(websocket_manager, last_message->opcode, last_message->data_len, last_message->data) != U_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error ulfius_websocket_send_message");
  }
}

void websocket_incoming_file_callback (const struct _u_request * request,
                                         struct _websocket_manager * websocket_manager,
                                         const struct _websocket_message * last_message,
                                         void * websocket_incoming_message_user_data) {
  char * my_message = msprintf("Incoming file %p, rsv: 0x%02x, opcode: 0x%02x, mask: %d, len: %zu", last_message, last_message->rsv, last_message->opcode, last_message->has_mask, last_message->data_len);
  y_log_message(Y_LOG_LEVEL_DEBUG, my_message);
  ulfius_websocket_send_message(websocket_manager, U_WEBSOCKET_OPCODE_TEXT, o_strlen(my_message), my_message);
  o_free(my_message);
}

/**
 * Ulfius main callback function that simply calls the websocket manager and closes
 */
int callback_websocket (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * websocket_user_data = o_strdup("my_user_data");
  int ret;
  
  if ((ret = ulfius_set_websocket_response(response, NULL, NULL, &websocket_manager_callback, websocket_user_data, &websocket_incoming_message_callback, websocket_user_data, &websocket_onclose_callback, websocket_user_data)) == U_OK) {
    ulfius_add_websocket_deflate_extension(response);
    return U_CALLBACK_CONTINUE;
  } else {
    return U_CALLBACK_ERROR;
  }
}

int callback_websocket_echo (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * websocket_user_data = o_strdup("my_user_data");
  int ret;
  
  y_log_message(Y_LOG_LEVEL_DEBUG, "Client connected to echo websocket");
  if ((ret = ulfius_set_websocket_response(response, NULL, NULL, NULL, NULL, &websocket_echo_message_callback, websocket_user_data, &websocket_onclose_callback, websocket_user_data)) == U_OK) {
    ulfius_add_websocket_deflate_extension(response);
    return U_CALLBACK_CONTINUE;
  } else {
    return U_CALLBACK_ERROR;
  }
}

int callback_websocket_file (const struct _u_request * request, struct _u_response * response, void * user_data) {
  int ret;
  
  if ((ret = ulfius_set_websocket_response(response, NULL, NULL, &websocket_manager_file_callback, NULL, &websocket_incoming_file_callback, NULL, &websocket_onclose_file_callback, NULL)) == U_OK) {
    ulfius_add_websocket_deflate_extension(response);
    return U_CALLBACK_CONTINUE;
  } else {
    return U_CALLBACK_ERROR;
  }
}

int
main(int argc, char **argv)
{
    int port = 0;
    int c;
    
    if (argc != 0) {
        while ((c = getopt(argc, argv, "p:c:k:hv")) != -1) {
            switch (c) {
                case 'p':
                    port = ator(optarg);
                    break;
                case 'h':
                    break;
                case 'v':
                    break;
                case 'c':
                    break;
                case 'k':
                    break;                    
                default:
                    abort();
            }
        }
    }

    if (!port) {
        port = DEFAULT_PORT;
    }

    log_init(stdout);

    log(LOG_INFO, log_string("msg", "starting micro-chat"), log_int("port", port));

    struct _u_request request;
    struct _u_response response;
    struct _websocket_client_handler websocket_client_handler = {NULL, NULL};

    char *url;
    sprintf(url, "wss://localhost:%d", port);

    ulfius_init_request(&request);
    ulfius_init_response(&response);

    if (ulfius_set_websocket_request(&request, url, "protocol", "permessage-deflate") == U_OK) {
        ulfius_add_websocket_client_deflate_extension(&websocket_client_handler);
        request.check_server_certificate = 0;
        if (ulfius_open_websocket_client_connection(&request, &websocket_manager_callback, websocket_user_data, &websocket_incoming_message_callback, websocket_user_data, &websocket_onclose_callback, websocket_user_data, &websocket_client_handler, &response) == U_OK) {
            //y_log_message(Y_LOG_LEVEL_DEBUG, "Wait for user to press <enter> to close the program");
            getchar();
            ulfius_websocket_client_connection_close(&websocket_client_handler);
            //y_log_message(Y_LOG_LEVEL_DEBUG, "Websocket closed");
        } else {
            //y_log_message(Y_LOG_LEVEL_ERROR, "Error ulfius_open_websocket_client_connection");
            o_free(websocket_user_data);
        }
    } else {
        //y_log_message(Y_LOG_LEVEL_ERROR, "Error ulfius_set_websocket_request");
        o_free(websocket_user_data);
    }

    ulfius_clean_request(&request);
    ulfius_clean_response(&response);

    return 0;
}
#endif
