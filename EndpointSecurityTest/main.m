//
//  main.m
//  EndpointSecurityTest
//
//  Created by Timm Kandziora on 18.06.19.
//  Copyright © 2019 Timm Kandziora. All rights reserved.
//

#import <Foundation/Foundation.h>

#include <dlfcn.h>
#include <EndpointSecurity/EndpointSecurity.h>

#define SOLVE_SYMBOL(handle, symbol, symbol_pointer) if (solve_symbol((handle), (symbol), (void**)&(symbol_pointer))) { NSLog(@"Couldn't solve %s ...", (symbol)); return 1; }

es_clear_cache_result_t (*_es_clear_cache)(es_client_t *client);
es_new_client_result_t (*_es_new_client)(es_client_t * _Nullable *client, es_handler_block_t handler);
es_return_t (*_es_delete_client)(es_client_t *client);
es_return_t (*_es_subscribe)(es_client_t *client, es_event_type_t *events, uint32_t event_count);
es_return_t (*_es_unsubscribe)(es_client_t *client, es_event_type_t *events, uint32_t event_count);
es_return_t (*_es_unsubscribe_all)(es_client_t *client);
size_t (*_es_message_size)(const es_message_t *msg);
es_message_t *(*_es_copy_message)(const es_message_t *msg);
es_string_token_t (*_es_exec_arg)(const es_event_exec_t *event, uint32_t index);
uint64_t (*_es_exec_arg_count)(const es_event_exec_t *event);
es_string_token_t (*_es_exec_env)(const es_event_exec_t *event, uint32_t index);
uint64_t (*_es_exec_env_count)(const es_event_exec_t *event);
es_return_t (*_es_mute_process)(es_client_t *client, audit_token_t audit_token);
es_respond_result_t (*_es_respond_auth_result)(es_client_t * _Nonnull client, const es_message_t * _Nonnull message, es_auth_result_t result, bool cache);
es_respond_result_t (*_es_respond_flags_result)(es_client_t *client, const es_message_t *message, uint32_t authorized_flags, bool cache);

int solve_symbol(void *handle, char *symbol, void **symbol_pointer)
{
    *symbol_pointer = dlsym(handle, symbol);
    
    return *symbol_pointer ? 0 : 1;
}

int solve_symbols(void *handle)
{
    SOLVE_SYMBOL(handle, "es_clear_cache", _es_clear_cache);
    SOLVE_SYMBOL(handle, "es_new_client", _es_new_client);
    SOLVE_SYMBOL(handle, "es_delete_client", _es_delete_client);
    SOLVE_SYMBOL(handle, "es_subscribe", _es_subscribe);
    SOLVE_SYMBOL(handle, "es_unsubscribe", _es_unsubscribe);
    SOLVE_SYMBOL(handle, "es_unsubscribe_all", _es_unsubscribe_all);
    SOLVE_SYMBOL(handle, "es_message_size", _es_message_size);
    SOLVE_SYMBOL(handle, "es_copy_message", _es_copy_message);
    SOLVE_SYMBOL(handle, "es_exec_arg", _es_exec_arg);
    SOLVE_SYMBOL(handle, "es_exec_arg_count", _es_exec_arg_count);
    SOLVE_SYMBOL(handle, "es_exec_env", _es_exec_env);
    SOLVE_SYMBOL(handle, "es_exec_env_count", _es_exec_env_count);
    SOLVE_SYMBOL(handle, "es_mute_process", _es_mute_process);
    SOLVE_SYMBOL(handle, "es_respond_auth_result", _es_respond_auth_result);
    SOLVE_SYMBOL(handle, "es_respond_flags_result", _es_respond_flags_result);
    
    return 0;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (geteuid() != 0) {
            NSLog(@"Please run me as root ...");
            return 0;
        }
        
        void *handle = dlopen("/usr/lib/libEndpointSecurity.dylib", RTLD_NOW);
        
        if (handle) {
            NSLog(@"Got handle at %p", handle);
        } else {
            NSLog(@"Couldn't get handle ...");
            return 0;
        }
        
        int ret = solve_symbols(handle);
        
        if (ret == 0) {
            NSLog(@"Successfully solved symbols");
        } else {
            NSLog(@"Couldn't solve symbols ...");
            return 0;
        }
        
        es_client_t *client = NULL;
        
        es_handler_block_t message_handler = [^void (es_client_t *client, es_message_t *message) {
            NSLog(@"Received message from subscribed event! Client at %p", client);
            
            NSLog(@"proc file path: %s", message->proc.file.path.data);
            NSLog(@"proc team id: %s", message->proc.team_id.data);
            NSLog(@"proc signing id: %s", message->proc.signing_id.data);
            NSLog(@"proc ppid: %d", message->proc.ppid);
            NSLog(@"proc original ppid: %d", message->proc.original_ppid);
            NSLog(@"event type: %u", message->event_type);
            NSLog(@"action type: %u", message->action_type);
            
            if (message->action_type == ES_ACTION_TYPE_NOTIFY) {
                NSLog(@"Notify action, doing nothing ...");
            } else {
                // It seems that for now all action types are auth or I somehow messed
                // up accessing the action union and notifys result type
                
                if (!strcmp("/usr/libexec/xpcproxy", message->proc.file.path.data)) {
                    es_event_exec_t exec = message->event.exec;
                    
                    NSLog(@"xpcproxy is our trampoline, we really: %s", exec.proc.file.path.data);
                }
                
                _es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
            }
        } copy];
        
        es_new_client_result_t client_result = _es_new_client(&client, message_handler);
        
        if (client_result == ES_NEW_CLIENT_RESULT_SUCCESS) {
            NSLog(@"Successfully got new client at %p", client);
        } else {
            NSLog(@"Couldn't get new client ...");
            if (client_result == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED) { NSLog(@"Error: not permitted"); }
            if (client_result == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED) { NSLog(@"Error: not entitled"); }
            return 0;
        }
        
        es_clear_cache_result_t cache_result = _es_clear_cache(client);
        
        if (cache_result == ES_CLEAR_CACHE_RESULT_SUCCESS) {
            NSLog(@"Successfully cleared cache");
        } else {
            NSLog(@"Couldn't clear cache ...");
        }
        
        es_event_type_t event = ES_EVENT_TYPE_AUTH_EXEC;
        es_return_t subscribe_result = _es_subscribe(client, &event, 1);
        
        if (subscribe_result == ES_RETURN_SUCCESS) {
            NSLog(@"Client subscribed successfully");
        } else {
            NSLog(@"Client didn't subscribe ...");
        }
        
        NSRunLoop *runLoop = [NSRunLoop currentRunLoop];
        [runLoop run];
        
        es_return_t unsubscribe_result = _es_unsubscribe_all(client);
        
        if (unsubscribe_result == ES_RETURN_SUCCESS) {
            NSLog(@"Successfully unsubscribed all events");
        } else {
            NSLog(@"Couldn't unsubscribe ...");
        }
        
        es_return_t delete_result = _es_delete_client(client);
        
        if (delete_result == ES_RETURN_SUCCESS) {
            NSLog(@"Successfully deleted client. Bye then.");
        } else {
            NSLog(@"Couldn't delete client. Oh oh ...");
        }
    }
    
    return 0;
}
