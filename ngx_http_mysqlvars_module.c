
/*
 * Copyright (C) Bearnard Hibbins
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <mysql/mysql.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libmemcached/memcached.h>
#include <openssl/sha.h>

 

typedef struct {
    MYSQL *db;
    char db_host[1000];
    int db_port;
    char db_before_sql[1000];
    char db_after_sql[1000];
    char db_database[100];
    char db_user[100];
    char db_passwd[100];
    char backend[100];
//    ngx_rbtree_t                     rbtree;
//    ngx_rbtree_node_t                sentinel;


} ngx_http_mysqlvars_conf_t;


typedef struct {
    ngx_str_t  *name;
    uintptr_t   data;
} ngx_http_mysqlvars_var_t;


typedef const char *(*ngx_http_mysqlvars_variable_handler_pt)(ngx_http_mysqlvars_conf_t  *gcf, char *host);

static ngx_int_t ngx_http_mysqlvars_docroot_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_mysqlvars_add_variables(ngx_conf_t *cf);
static void *ngx_http_mysqlvars_create_conf(ngx_conf_t *cf);
static char *ngx_http_mysqlvars_docroot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mysqlvars_db_sql(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *MysqlVars_docroot_by_host (ngx_http_mysqlvars_conf_t  *gcf, char *host);
static void ngx_http_mysqlvars_cleanup(void *data);



static ngx_command_t  ngx_http_mysqlvars_commands[] = {

    { ngx_string("mysqlvars_db"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_mysqlvars_docroot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("mysqlvars_db_sql"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_mysqlvars_db_sql,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_mysqlvars_module_ctx = {
    ngx_http_mysqlvars_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_mysqlvars_create_conf,            /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_mysqlvars_module = {
    NGX_MODULE_V1,
    &ngx_http_mysqlvars_module_ctx,            /* module context */
    ngx_http_mysqlvars_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
        NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_mysqlvars_vars[] = {


    { ngx_string("mysqlvars_docroot"), NULL, ngx_http_mysqlvars_docroot_variable,
      (uintptr_t) MysqlVars_docroot_by_host, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};



static ngx_int_t
ngx_http_mysqlvars_docroot_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_mysqlvars_variable_handler_pt  handler =
        (ngx_http_mysqlvars_variable_handler_pt) data;


    char host[100];
    char hostrest[100];
    const char             *val; // = "/var/www/tests/1";
    ngx_http_mysqlvars_conf_t  *gcf;

    gcf = ngx_http_get_module_main_conf(r, ngx_http_mysqlvars_module);

    if (gcf->db == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "DEBUG: mysql init failed in ngx_http_mysqlvars_docroot_variable ");
        goto not_found;
    }


    if (r->headers_in.host == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "DEBUG: no host header provided in ngx_http_mysqlvars_docroot_variable ");
        return NGX_ERROR;
    }
    //host = r->headers_in.host->value.data;
    sscanf((char *) r->headers_in.host->value.data, "%999[^:]:%999[^\n]", host, hostrest);    
        // ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
        //                   "http request line: \"%V\"", &r->request_line);
        // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        //             "DEBUG3: in ngx_http_mysqlvars_docroot_variable %V", &r->headers_in.host->value);


    val = handler(gcf, host);
        // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        //              "DEBUG34: in ngx_http_mysqlvars_docroot_variable %s", val);

    if (val == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "DEBUG: value returned from the db was null in ngx_http_mysqlvars_docroot_variable ");
        goto not_found;
    }
        // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        //              "DEBUG5: in ngx_http_mysqlvars_docroot_variable ");

    v->len = ngx_strlen(val);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) val;
        // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        //             "DEBUG6: in ngx_http_mysqlvars_docroot_variable ");

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_mysqlvars_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_mysqlvars_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_mysqlvars_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_mysqlvars_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mysqlvars_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_mysqlvars_cleanup;
    cln->data = conf;

    return conf;
}


static char *
ngx_http_mysqlvars_docroot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mysqlvars_conf_t  *gcf = conf;

    ngx_str_t  *value;
    int num_args = 0;


    
    if (gcf->db) {
        return "is duplicate";
    }

    value = cf->args->elts;

    gcf->db = mysql_init(NULL);
    num_args = sscanf((char *) value[1].data, "%99[^:]://%99[^:]:%99[^@]@%99[^:]:%99d/%99[^\n]", gcf->backend, gcf->db_user, gcf->db_passwd, gcf->db_host, &gcf->db_port, gcf->db_database);

    if (num_args != 6){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid uri configured for mysqlvars module: %s , uri should be formatted as mysql://username:password@localhost.localdomain:3306/Hosts", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (gcf->db == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "mysql_init(\"%V\") failed", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

}

static char *
ngx_http_mysqlvars_db_sql(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mysqlvars_conf_t  *gcf = conf;

    ngx_str_t  *value;

    int num_args = 0;

    /*if (gcf->db_sql) {
        return "is duplicate";
    }
    */

    value = cf->args->elts;

    //gcf->db_sql = value;
    num_args = sscanf((char *) value[1].data, "%999[^@]@%999[^\n]", gcf->db_before_sql, gcf->db_after_sql);

    if (num_args != 2){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sql template configured for mysqlvars module: %s , uri should be formatted as mysql://username:password@localhost.localdomain:3306/Hosts", &value[1]);
        return NGX_CONF_ERROR;
    }


    /*if (gcf->db_sql == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "mysql_init(\"%V\") failed", &value[1]);
        return NGX_CONF_ERROR;
    }
    */
    return NGX_CONF_OK;
}


static char *MysqlVars_docroot_by_host(ngx_http_mysqlvars_conf_t  *gcf, char *host) {



        MYSQL *db;
        MYSQL_ROW row;
        MYSQL_RES *res = NULL;
        //FILE *fp;

        
        char *buffer;

        char new_sql[1000];

        sprintf(new_sql,"%s%s%s", gcf->db_before_sql, host, gcf->db_after_sql);

////////////// HASH /////////////
// here we could make use of sha1 or md5

        unsigned char key[SHA_DIGEST_LENGTH];

        char *hash = (char *) malloc( sizeof(char) * ((SHA_DIGEST_LENGTH*2)+1) );
        char *hashp = hash;

        SHA1((unsigned char*) new_sql, strlen(new_sql), key);



        // here we cycle through each byte of the digest and convert it into a hex string by moving the pointer along as we go
        int i;
        for ( i = 0; i < SHA_DIGEST_LENGTH; i++, hashp += 2 ) {
            snprintf ( hashp, 3, "%02x", key[i] );
        }

        //ngx_str_t val;
        //val =  ngx_hash_find(gcf->keys.keys, 0, ngx_string(hash), strlen(hash));

///////////// MEMCACHED //////////////

        uint32_t flags;
        char *return_value;
        size_t return_value_length;

        memcached_return_t return_error;
        memcached_server_st *servers = NULL;
        memcached_st *memc;
        memcached_return rc;
        memc= memcached_create(NULL);
        servers= memcached_server_list_append(servers, gcf->db_host, 11211, &rc);
    rc= memcached_server_push(memc, servers);
        
        if (!(rc == MEMCACHED_SUCCESS)){
                goto mysql;
        }
           
        return_value= memcached_get(memc, hash, strlen(hash),  &return_value_length, &flags, &return_error);

        if((return_value) != NULL){
                free(hash); 
                memcached_free(memc);
                free(servers);
                
           return return_value;
        }
       
        goto mysql;
/////////// MYSQL ////////////////////
        mysql:
        
        db = mysql_init(NULL);
        if(db == NULL){
           goto mysql_fail;  
        }

        if (!mysql_real_connect(db, gcf->db_host, gcf->db_user, gcf->db_passwd, gcf->db_database, 0, NULL, 0)) {
           goto mysql_fail;  
        }

        if (mysql_query(db, new_sql)) {
           goto mysql_fail;  
        }


        if (!(res = mysql_store_result(db))){
           goto mysql_fail;  
        }
        row = mysql_fetch_row(res);
        //if ((buffer = malloc(sizeof(row[0]))) == NULL) {
        if ((buffer = malloc(1000)) == NULL) {

            goto mysql_fail;  
        }

        if(!(res == NULL))
           strcpy(buffer, row[0]);
        mysql_free_result(res);
        mysql_close(db);

//////// MEMCACHE SET /////////

         if(rc == MEMCACHED_SUCCESS)
            rc= memcached_set(memc, hash, strlen(hash), buffer, strlen(buffer), (time_t)300, (uint32_t)0);
                // could check rc and log or something
        goto mysql_success;

        mysql_fail:
        mysql_free_result(res);
        mysql_close(db);
                free(hash);
                memcached_free(memc);
        free(servers);
        return "/var/www/sitenotfound";

                mysql_success:
                free(hash);
                memcached_free(memc);
        free(servers);
        return buffer;
}

static void
ngx_http_mysqlvars_cleanup(void *data)
{
    ngx_http_mysqlvars_conf_t  *gcf = data;

    if (gcf->db) {
        mysql_close(gcf->db);
    }

}


