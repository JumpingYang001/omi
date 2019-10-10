#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
# include <pwd.h>
# include <string.h>
# include <grp.h>
int SetUser(uid_t uid, gid_t gid)
{
    if (setgid(gid) != 0)
    {
        printf("trace_setgid_Failed: error = %d\n",errno);
        return -1;
    }

    /*
     * Limit the groups that this user is in to the ones in /etc/groups.
     * Without this it includes the root group if root called Setuser()
     */
    {
        struct passwd pwbuf;
        char buf[1024];
        struct passwd* pw;

        if (getpwuid_r(uid, &pwbuf, buf, sizeof(buf), &pw) != 0 || !pw)
        {
            printf("trace_getpwuidr_Failed: error = %d\n",errno);
            return -1;
        }

        if (initgroups(pw->pw_name, gid) != 0)
        {
            printf("trace_initgroups_Failed: error = %d\n",errno);
            return -1;
        }
    }

    if (setuid(uid) != 0)
    {
        printf("trace_setuid_Failed: error = %d\n",errno);
        return -1;
    }

    return 0;
}

int IsRoot()
{
    uid_t uid = geteuid();
    
    return uid == 0 ? 0 : -1;
}
int LookupUser(const char* user, uid_t* uid, gid_t* gid)
{
    char buf[1024];
    struct passwd pwd;
    struct passwd* ppwd = 0;

    int r = getpwnam_r(user, &pwd, buf, sizeof(buf), &ppwd);
    if (NULL == ppwd || r != 0)
    {
        printf("trace_getpwnamr_Failed: error = %d\n",errno);
        return -1;
    }

    *uid = pwd.pw_uid;
    *gid = pwd.pw_gid;
    return 0;
}
static char** _DuplicateArgv(int argc, char* argv[])
{
    int i;

    char **newArgv = (char**)malloc((argc+5)*sizeof(char*));
    if (!newArgv) 
    {
        return NULL;
    }

    /* argv[0] will be filled in later*/
    if (argc > 1)
    {
        for (i = 1; i<argc; ++i)
        {
            newArgv[i] = (char*)argv[i];
        }
    }

    newArgv[argc] = "--logfilefd";
    newArgv[argc+1] = NULL;
    newArgv[argc+2] = "--socketpair";
    newArgv[argc+3] = NULL;  /* to be filled later*/
    newArgv[argc+4] = NULL;

    return newArgv;
}
static char** _DuplicateEnvp(char* envp[])
{
    int i;

    /*Special env variables:*/

    static const char Krb5_Trace[]  = "KRB5_TRACE=";
    static const char Krb5_KTName[] = "KRB5_KTNAME=";
    static const char Krb5_CCName[] = "KRB5_CCNAME=";
    static const char Ntlm_User_File[] = "NTLM_USER_FILE=";

    static const char Krb5_Trace_Default[]  = "KRB5_TRACE=/dev/stderr";

    static const char *REQUIRED_ENV[] = {
                               Krb5_Trace,
                               Krb5_KTName,
                               Krb5_CCName,
                               Ntlm_User_File,
                               NULL
                            };
      

    int env_count = 0;
    int new_env_count = 0;
    int trace_set = 0;
    char *strp = NULL;
    char *krb5KeytabPath    = "/etc/krb5.keytab";
    char *krb5CredCacheSpec = "FILE:/tmp/omi_cc";
    if (envp)
    {
        char *envitem = NULL;
        for (envitem = (char*)(envp[0]); envitem; envitem = (char*)(envp[env_count]))
        { 
            env_count++;
        }
    }

    char **newEnv = (char**)malloc((sizeof(REQUIRED_ENV))*sizeof(char*));
    if (!newEnv)
    {
        goto err;
    }

    for (i = 1; i < env_count; ++i)
    {
        if ( strncmp(Krb5_Trace, envp[i], sizeof(Krb5_Trace)-1) == 0 ) 
        {
            trace_set = 1;
            newEnv[new_env_count] = (char*)strdup(envp[i]);
            if (!newEnv[new_env_count])
            {
                goto err;
            }
            new_env_count++;
        }
    }

    /* Trace
We respect KRB5_TRACE set in the environment, but if it is not set we still set it if the log level
is info or debug*/

    int logLevel=5;
    if (logLevel > 2 && !trace_set)
    {
        newEnv[new_env_count] = malloc(sizeof(Krb5_Trace_Default));
        if (!newEnv[new_env_count])
        {
            goto err;
        }
        strp = newEnv[new_env_count];
        memcpy(strp, Krb5_Trace_Default, sizeof(Krb5_Trace_Default));
        new_env_count++;
    }

    /* Keytab*/
    newEnv[new_env_count] = malloc(sizeof(Krb5_KTName)+strlen(krb5KeytabPath));
    if (!newEnv[new_env_count])
    {
        goto err;
    }
    strp = newEnv[new_env_count];
    new_env_count++;
 
    memcpy(strp, Krb5_KTName, sizeof(Krb5_KTName)-1);
    strp += sizeof(Krb5_KTName)-1;
    memcpy(strp, krb5KeytabPath, strlen(krb5KeytabPath)+1);

    /*Cred Cache*/
    newEnv[new_env_count] = malloc(sizeof(Krb5_CCName)+strlen(krb5CredCacheSpec));
    if (!newEnv[new_env_count])
    {
        goto err;
    }
    strp = newEnv[new_env_count];
    new_env_count++;
 
    memcpy(strp, Krb5_CCName, sizeof(Krb5_CCName)-1);
    strp += sizeof(Krb5_CCName)-1;
    memcpy(strp, krb5CredCacheSpec, strlen(krb5CredCacheSpec)+1);

    /*NTLM USer file*/
    char *ntlm_user_file = getenv("NTLM_USER_FILE");
    if (ntlm_user_file)
    {
        newEnv[new_env_count] = malloc(sizeof(ntlm_user_file)+strlen(ntlm_user_file));
        if (!newEnv[new_env_count])
        {
            goto err;
        }
        strp = newEnv[new_env_count];
        new_env_count++;
        memcpy(strp, ntlm_user_file, sizeof(ntlm_user_file)-1);
        strp += sizeof(ntlm_user_file)-1;
        memcpy(strp, ntlm_user_file, strlen(ntlm_user_file)+1);
    }

  /*  newArgv[argc+1] = NULL; */
    newEnv[new_env_count++] = NULL;

    return newEnv;

err:

    if (newEnv)
    {
        int i = 0;
        for (i = 0; i < new_env_count; i++ )
        {
            if (newEnv[i])
            {
                free(newEnv[i]);
                newEnv[i] = NULL;
            }
        }
        free(newEnv);
    }
    return NULL;
}
int main(int argc, char *argv[], char **envp) {
  char **engine_argv = NULL;
  char **engine_envp = NULL;
  pid_t pid;
  printf("Main program started\n");
  engine_argv = _DuplicateArgv(argc, argv);
  engine_envp = _DuplicateEnvp(envp);
  /*char* argv[] = { "value1", NULL }*/;
  /*char* envp[] = { "some", "environment", NULL };*/
if ((pid = fork()) ==-1)
{
      perror("fork error");
      return 1;
}
else if (pid == 0) { //child
    if (0 == IsRoot())
    {
        printf("I am root!\n");
        char* serviceAccount="omi";
        uid_t serviceAccountUID=-1;
        gid_t serviceAccountGID=-1;
        if (LookupUser(serviceAccount, &serviceAccountUID, &serviceAccountGID) != 0) 
         { 
             err("invalid service account:  %s", serviceAccount); 
         } 
        printf("found omi user!\n");

        if (SetUser(serviceAccountUID, serviceAccountGID) != 0)
        {
            err("failed to change uid/gid of engine");
        }  
         printf("set to omi user!\n");
    }

    if(execve("/home/testuser/fakeOMIEngine", engine_argv, (char * const*) engine_envp) == -1)
    {
      perror("Could not execve");
      printf("child: error = %d\n",errno);
      fprintf(stderr, "Oops!\n");
      return 1;
    }
}
else if(pid > 0) { //parent
    printf("Main program ended\n");
}
else{
  printf("pid < 0\n");
  printf("child: error = %d\n",errno);
}
    return 0;
}