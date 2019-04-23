#define pr_fmt(fmt) "cs423_mp4: " fmt

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
#include <linux/string.h>
#include "mp4_given.h"
/**
 * get_inode_sid - Get the inode mp4 security label id
 *
 * @inode: the input inode
 *
 * @return the inode's security id if found.
 *
 */
static int get_inode_sid(struct inode *inode)
{ 
       //  int sid;

        struct dentry *dentry;
#define INITCONTEXTLEN 255
        char *context = NULL;
        unsigned len = 0;
        int rc = 0;
        dentry = d_find_alias(inode);
        if(!dentry){
         printk("Cannot find the dentry of correspodant inode\n");
         return -1;
       }
        len = INITCONTEXTLEN;
         context = kmalloc(len+1, GFP_NOFS);
         if (!context) {
         rc = -ENOMEM;
         dput(dentry);
           // goto out_unlock;
           }

       context[len]='\0';
       rc=inode->i_op->getxattr(dentry,XATTR_NAME_MP4,context,len);
       dput(dentry);
       return  __cred_ctx_to_sid(context);      
}

/**
 NITCONTEXTLEN;
                context = kmalloc(len+1, GFP_NOFS);
                if (!context) {
                        rc = -ENOMEM;
                        dput(dentry);
                        goto out_unlock;
                }* mp4_bprm_set_creds - Set the credentials for a new task
 *
 * @bprm: The linux binary preparation structure
 *
 * returns 0 on success.
 *
**/
static int mp4_bprm_set_creds(struct linux_binprm *bprm)
{
	/*
	 * Add your code here
	 * ...
	 */
    struct inode *inode = file_inode(bprm->file);
    int sid= get_inode_sid(inode);
    if(sid==MP4_TARGET_SID){

     bprm->cred->security->mp4_flags=MP4_TARGET_SID;
  }

	return 0;
}

/**
 * mp4_cred_alloc_blank - Allocate a blank mp4 security label
 *
 * @cred: the new credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	/*
	 * Add your code here
	 * ...
	 */
     //   struct task_security_struct *tsec;
        struct mp4_security * tsec;
        tsec = kzalloc(sizeof(struct mp4_security), gfp);
        if (!tsec)
                return -ENOMEM;

        tsec->mp4_flags=MP4_NO_ACCESS;
        cred->security = tsec;
        return 0;
}


/**
 * mp4_cred_free - Free a created security label
 *
 * @cred: the credentials struct
 *
 */
static void mp4_cred_free(struct cred *cred)
{
        struct mp4_security  *tsec = cred->security;

        /*
         * cred->security == NULL if security_cred_alloc_blank() or
         * security_prepare_creds() returned an error.
         */
        BUG_ON(cred->security && (unsigned long) cred->security < PAGE_SIZE);
        cred->security = (void *) 0x7UL;
        kfree(tsec);
	/*
	 * Add your code here
	 * ...
	 */
}

/**
 * mp4_cred_prepare - Prepare new credentials for modification
 *
 * @new: the new credentials
 * @old: the old credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
 {      const struct mp4_security *old_tsec;
        struct mp4_security  *tsec;

        old_tsec = old->security;

        tsec = kmemdup(old_tsec, sizeof(struct mp4_security), gfp);
        if (!tsec)
                return -ENOMEM;

        new->security = tsec;
        return 0;
}

/**
 * mp4_inode_init_security - Set the security attribute of a newly created inode
 *
 * @inode: the newly created inode
 * @dir: the containing directory
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * returns 0 if all goes well, -ENOMEM if no memory, -EOPNOTSUPP to skip
 *
 */
static int mp4_inode_init_security(struct inode *inode, struct inode *dir,
				   const struct qstr *qstr,
				   const char **name, void **value, size_t *len)
{
	/*
	 * Add your code here
	 * ...
	 */
    struct mp4_security* tsec=current_security();
   
    if(tsec->mp4_flags==MP4_TARGET_SID){

        if (name)
                *name = XATTR_NAME_MP4;

        if (value && len) {

                string s="read-write";
                size_t clen=strlen(s);

                *value = s;
                *len = clen;
        }
    }
	return 0;
}

static int mp4_mac_policy(int ssid,int osid ,int mask){


}

/**
 * mp4_has_permission - Check if subject has permission to an object
 *
 * @ssid: the subject's security id
 * @osid: the object's security id
 * @mask: the operation mask
 *
 * returns 0 is access granter, -EACCES otherwise
 *
 */
static int mp4_has_permission(int ssid, int osid, int mask)
{
  if(ssid==MP4_TARGET_SID){


    }	/*
	 * Add your code here
	 * ...
	 */
	return 0;
}

/**
 * mp4_inode_permission - Check permission for an inode being opened
 *
 * @inode: the inode in question
 * @mask: the access requested
 *
 * This is the important access check hook
 *
 * returns 0 if access is granted, -EACCES otherwise
 *
 */
static int mp4_inode_permission(struct inode *inode, int mask)
{
     const struct cred *cred=current_cred();
     
     int ssid=cred->security->mp4_flags;

     int osid=get_inode_sid(inode);

     int rc;
     mask &= (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);
     if(mask==0)
           return 0;

     rc= mp4_has_permission(ssid,osid,mask);
     
     if(rc==0)
	return 0;
     else  
        return -EACCES;
}


/*
 * This is the list of hooks that we will using for our security module.
 */
static struct security_hook_list mp4_hooks[] = {
	/*
	 * inode function to assign a label and to check permission
	 */
	LSM_HOOK_INIT(inode_init_security, mp4_inode_init_security),
	LSM_HOOK_INIT(inode_permission, mp4_inode_permission),

	/*
	 * setting the credentials subjective security label when laucnhing a
	 * binary
	 */
	LSM_HOOK_INIT(bprm_set_creds, mp4_bprm_set_creds),

	/* credentials handling and preparation */
	LSM_HOOK_INIT(cred_alloc_blank, mp4_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, mp4_cred_free),
	LSM_HOOK_INIT(cred_prepare, mp4_cred_prepare)
};

static __init int mp4_init(void)
{
	/*
	 * check if mp4 lsm is enabled with boot parameters
	 */
	if (!security_module_enable("mp4"))
		return 0;

	pr_info("mp4 LSM initializing..");

	/*
	 * Register the mp4 hooks with lsm
	 */
	security_add_hooks(mp4_hooks, ARRAY_SIZE(mp4_hooks));

	return 0;
}

/*
 * early registration with the kernel
 */
security_initcall(mp4_init);
