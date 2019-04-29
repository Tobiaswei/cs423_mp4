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


#define DEBUG 1
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
     /*   pr_err("Get into get_inode_sid");

        struct dentry *dentry;
#define INITCONTEXTLEN 255
        char *context = NULL;
        unsigned len = 0;
        int rc = 0;
        int sid;
        dentry = d_find_alias(inode);
        if(!dentry){
         pr_err("Cannot find the dentry of correspodant inode");
         return MP4_NO_ACCESS;
       }
        len = INITCONTEXTLEN;
         context = kmalloc(len+1, GFP_NOFS);
         if (!context) {
              if(dentry)
                   dput(dentry);
          
           return MP4_NO_ACCESS;
           // goto out_unlock;
           }

       context[len]='\0';
       rc=inode->i_op->getxattr(dentry,XATTR_NAME_MP4,context,len);
       pr_debug("The conext is %s",context);
       pr_debug("the value of rc is %d",rc);
       if(dentry)
            dput(dentry);
      
       if(rc<0){

           kfree(context);
           return 0;  
     } 
      else{
       sid=__cred_ctx_to_sid(context);
       kfree(context);
  }
    if(printk_ratelimit()){

         pr_info("mp4 : get node helper passed!");
  }
       return sid;
*/

	struct dentry *dentry;
	int size;
	int ret;
	char *cred_ctx;
	int sid;

	//error handling for inode
	if (!inode || !inode->i_op || !inode->i_op->getxattr) {
		return MP4_NO_ACCESS;
	}

	//get dentry of inode
	dentry = d_find_alias(inode);

	//error handling dentry
	if (!dentry) {
		return MP4_NO_ACCESS;
	}

	size = 128;
	cred_ctx = kmalloc(size, GFP_KERNEL);
	if(!cred_ctx) {
		if(dentry)
			dput(dentry);
		return MP4_NO_ACCESS;
	}

	//first time get xattr and error handling
	ret = inode->i_op->getxattr(dentry, XATTR_MP4_SUFFIX, cred_ctx, size);
	size = ret;

	if(ret == -ERANGE) {
		//buffer overflows, should query the correct buffer size
		kfree(cred_ctx);
		ret = inode->i_op->getxattr(dentry, XATTR_MP4_SUFFIX, NULL, 0);
		//queried size even < 0, error, terminate.
		if(ret < 0) {
			if(dentry)
				dput(dentry);
			return MP4_NO_ACCESS;
		}

		//update the size by the newly queried correct size
		size = ret;
		cred_ctx = kmalloc(size, GFP_KERNEL);
		if(!cred_ctx) {
			if(dentry)
				dput(dentry);
			return -ENOMEM;
		}
		//second time get xattr and error handling
		ret = inode->i_op->getxattr(dentry, XATTR_MP4_SUFFIX, cred_ctx, size);
	}

	if(dentry)
		dput(dentry);

	if(ret < 0) {
		kfree(cred_ctx);
		return MP4_NO_ACCESS;
	} else {
		cred_ctx[size] = '\0';
		sid = __cred_ctx_to_sid(cred_ctx);
		kfree(cred_ctx);
	}

	if(printk_ratelimit()) {
		pr_info("mp4: get node sid helper passed!");
	}

	return sid;



}

/**
 *
 * @bprm: The linux binary preparation structure
 *
 * returns 0 on success.
 *
**/
static int mp4_bprm_set_creds(struct linux_binprm *bprm)
{
  if(!bprm){
     pr_err("brpm is not existed");
     return -ENOENT;
   }

  if(!bprm->cred){
      pr_err("Cred is not existed");
      return -ENOENT;
   }

   if(!bprm->cred->security){
         pr_err("security is not existed");
         return -ENOENT;
 }
   if(!bprm->file){

      pr_err("File is not existed");
      return -ENOENT;
 }

    if(!bprm->file->f_inode){

    pr_err("Inode is not existed");
    return -ENOENT;
 }
   if (bprm->cred_prepared) return 0;

   struct mp4_security * tsec;
   // check bprm->file
   struct inode *inode;
   inode = bprm->file->f_inode;
   int sid= get_inode_sid(inode);
    

   if(sid==MP4_TARGET_SID){
      
      // pr_err("set targt bolb security as MP4_TARGET_SID");
        
       tsec=bprm->cred->security;

       tsec->mp4_flags=MP4_TARGET_SID;
    }
  
        // pr_err("Cannot find the target xattr in corresponding bprm file");      
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
       if(!cred){

               pr_err("No credential in allocate  blank");
               return -ENOENT;
       }          

        struct mp4_security * tsec;

        tsec = kzalloc(sizeof(struct mp4_security), gfp);

        if (!tsec)
                return -ENOMEM;

        tsec->mp4_flags=MP4_NO_ACCESS;

        cred->security=tsec;
       
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
        if(!cred->security){
           pr_err("mp4_cred_free no cred passed into");
           return -ENOENT;
 
      }
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
 {     
        if(!new || !old){
 
          pr_err("mp4_cred_prepare no new or old passed into");
          return -ENOENT;
       } 

        const struct mp4_security *old_tsec;

        struct mp4_security  *tsec=NULL;
 
        old_tsec = old->security;
    
        if(!old_tsec){
                           
             mp4_cred_alloc_blank(new,gfp);
         }

        else
           {
		   tsec = kmemdup(old_tsec, sizeof(struct mp4_security), gfp);
                   if (!tsec)
                     return -ENOMEM;

                new->security = tsec;

	   }
        
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
    if(!current_security()) return -EOPNOTSUPP;
    
    if(!inode||!dir) return -EOPNOTSUPP;

    struct mp4_security* tsec=current_security();
    if (name){

                *name = XATTR_NAME_MP4;
        }

      else return -ENOMEM; 

    if(tsec->mp4_flags!=MP4_TARGET_SID){
        return -EOPNOTSUPP;
      }   
   else {

             
        if (value && len) {

                char *s="read-write";
                size_t clen=strlen(s);

                *value = s;
                *len = clen;
        }
        else return -ENOMEM;
    }

	return 0;
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
static int mp4_has_permission(int ssid, int  osid , int mask)
{
     if(osid ==MP4_NO_ACCESS){
               
            if(ssid == MP4_TARGET_SID){

               pr_info("ssid : %d , osid : %d  mask :%d cannot access to inode",ssid,osid,mask);
               return -EACCES;
           }

            else return 0;       
       } 
          
       if(osid==MP4_READ_OBJ) {

             if(mask==MAY_READ) return 0;
            
              else return -EACCES;
      }
         
        if(osid==MP4_READ_WRITE){
              
              if(ssid==MP4_TARGET_SID){
                  if((mask |  MAY_READ  | MAY_WRITE | MAY_APPEND)==(MAY_READ  | MAY_WRITE | MAY_APPEND)) return 0;
                   else return  -EACCES;       
                }
              else{
                 if(mask==MAY_READ) return 0;
                 else return -EACCES;
              }

        }  

 
       if(osid==MP4_WRITE_OBJ){

              if(ssid==MP4_TARGET_SID){
                   if((mask |  MAY_WRITE | MAY_APPEND)== ( MAY_WRITE | MAY_APPEND)) return 0;
                   else return -EACCES; 
                   }
              else{
                   if(mask==MAY_READ) return 0;
                   else return -EACCES;
               }
       }

       if(osid==MP4_EXEC_OBJ){
         
               if((mask| MAY_EXEC | MAY_READ) == (MAY_EXEC| MAY_READ)) return 0;
               else return -EACCES;
       }
       if(osid==MP4_READ_DIR && ssid==MP4_TARGET_SID){
            
               if(mask| MAY_EXEC | MAY_READ | MAY_ACCESS==MAY_ACCESS| MAY_EXEC| MAY_READ) return 0;
                else return -EACCES;
       }

       if((osid==MP4_RW_DIR)  && (ssid ==MP4_TARGET_SID)){
               
                return 0;
       }

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
     int rc=0; 

     const struct cred *cred=current_cred();

     struct mp4_security* new_sec;
     
     int ssid;

     struct dentry * _dentry;
    //Sanity check all the identities used in these function!

     if(!inode) return -EACCES;

     mask &= (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);
     
     if(!mask) return 0;// no mask operation grant pass
     
     if(!cred || !cred->security){
        
            pr_err("mp4_inode_perimission : cred or cred->security is NULL");
   
            return -EACCES;  
      }

     new_sec =cred->security;

     ssid=new_sec->mp4_flags;
    
  #define BUFFLEN 255

    _dentry=d_find_alias(inode);

    if(!_dentry ){
         
         //dput(_dentry);

        return -EACCES;

    }     
     //allocate memory for buff
  
     char * buff=NULL;
     int  len = BUFFLEN;
     char * dir;

     buff = kmalloc(len+1, GFP_NOFS);
    
     if(!buff){
          
         pr_err("Allocation failure for buff");
         
         if(_dentry)
             dput(_dentry);
        
         return 0;  
     
     }
    
     dir= dentry_path_raw(_dentry, buff,len+1);
    
     if(printk_ratelimit())
         pr_info("The directory :%s",dir);

     if(!dir){
        kfree(buff);
        if(_dentry)
            dput(_dentry);
      return -EACCES;

      }
     if (mp4_should_skip_path(dir)) {

	  kfree(buff);
	  if(_dentry)
		dput(_dentry);
	  return 0; 
    }
 
   int osid;

   osid= get_inode_sid(inode);

   if(ssid==MP4_TARGET_SID){
        
          if(mp4_has_permission(ssid,osid,mask)==0) rc=0;
            
          else{
                pr_err("permission Denied ssid: %d , osid : %d mask : %d", ssid,osid, mask);
                rc =-EACCES;
             }  // return  -EACCES;
    }

  else{

    if(S_ISDIR(inode->i_mode)) rc=0;

    else{
 

         if(mp4_has_permission(ssid,osid,mask)==0) rc= 0;
      
         else{

            pr_err("permission Denied ssid :%d, osid %d mask :%d", ssid , osid , mask);

            rc= -EACCES;
         }// return -EACCES;
    }

 
  }	

    if (rc==0 && printk_ratelimit()) pr_info("Grant Access successfully for the following path : %s",dir);
    
    else if(rc==-EACCES && printk_ratelimit()) pr_info("Grant DENIED Access  for the following path : %s",dir);
    
     kfree(buff);

     if(_dentry)
          dput(_dentry);

     if (rc==0) return 0;

     else return -EACCES;
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
