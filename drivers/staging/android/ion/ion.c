// SPDX-License-Identifier: GPL-2.0
/*
<<<<<<< HEAD

 * drivers/staging/android/ion/ion.c
 *
=======
>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/dma-buf.h>
#include <linux/memblock.h>
#include <linux/miscdevice.h>
#include <linux/msm_dma_iommu_mapping.h>
#include <linux/msm_ion.h>
#include <linux/uaccess.h>

#include "ion.h"
#include "ion_priv.h"
#include "compat_ion.h"

struct ion_device {
	struct miscdevice dev;
	struct plist_head heaps;
	struct rw_semaphore heap_lock;
	long (*custom_ioctl)(struct ion_client *client, unsigned int cmd,
			     unsigned long arg);
};

struct ion_client {
	struct ion_device *dev;
	struct rb_root handles;
	struct rb_node node;
	struct idr idr;
	rwlock_t idr_lock;
	rwlock_t rb_lock;
};

struct ion_handle {
	struct ion_buffer *buffer;
	struct ion_client *client;
	struct rb_node node;
	atomic_t kmap_cnt;
	atomic_t refcount;
	int id;
};

struct ion_vma_list {
	struct list_head list;
	struct vm_area_struct *vma;
};

static struct kmem_cache *ion_sg_table_pool;
static struct kmem_cache *ion_page_pool;

static bool ion_buffer_fault_user_mappings(struct ion_buffer *buffer)
{
	return !(buffer->flags & ION_FLAG_CACHED_NEEDS_SYNC) &&
		 buffer->flags & ION_FLAG_CACHED;
}

static struct page *ion_buffer_page(struct page *page)
{
	return (struct page *)((unsigned long)page & ~(1UL));
}

static bool ion_buffer_page_is_dirty(struct page *page)
{
	return (unsigned long)page & 1UL;
}

static void ion_buffer_page_dirty(struct page **page)
{
	*page = (struct page *)((unsigned long)(*page) | 1UL);
}

static void ion_buffer_page_clean(struct page **page)
{
	*page = (struct page *)((unsigned long)(*page) & ~(1UL));
}

static struct ion_buffer *ion_buffer_create(struct ion_heap *heap,
					    struct ion_device *dev,
					    unsigned long len,
					    unsigned long align,
					    unsigned long flags)
{
	struct ion_buffer *buffer;
	struct scatterlist *sg;
	struct sg_table *table;
	int i, ret;

	buffer = kmalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	*buffer = (typeof(*buffer)){
		.dev = dev,
		.heap = heap,
		.flags = flags,
		.size = len,
		.vmas = LIST_HEAD_INIT(buffer->vmas),
		.kmap_lock = __MUTEX_INITIALIZER(buffer->kmap_lock),
		.page_lock = __MUTEX_INITIALIZER(buffer->page_lock),
		.vma_lock = __MUTEX_INITIALIZER(buffer->vma_lock),
		.ref = {
			.refcount = ATOMIC_INIT(1)
		}
	};

	ret = heap->ops->allocate(heap, buffer, len, align, flags);
	if (ret) {
		if (!(heap->flags & ION_HEAP_FLAG_DEFER_FREE))
			goto free_buffer;

		ion_heap_freelist_drain(heap, 0);
		ret = heap->ops->allocate(heap, buffer, len, align, flags);
		if (ret)
			goto free_buffer;
	}

	table = heap->ops->map_dma(heap, buffer);
<<<<<<< HEAD
	if (WARN_ONCE(table == NULL,
			"heap->ops->map_dma should return ERR_PTR on error"))
		table = ERR_PTR(-EINVAL);
	if (IS_ERR(table)) {
		heap->ops->free(buffer);
		kfree(buffer);
		return ERR_CAST(table);
	}
=======
	if (IS_ERR_OR_NULL(table))
		goto free_heap;

>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance
	buffer->sg_table = table;
	if (ion_buffer_fault_user_mappings(buffer)) {
		int num_pages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
		int j, k = 0;

<<<<<<< HEAD
		buffer->pages = vmalloc(array_size(num_pages, sizeof(struct page *)));
		if (!buffer->pages) {
			ret = -ENOMEM;
			goto err1;
		}
=======
		buffer->pages = vmalloc(sizeof(*buffer->pages) * num_pages);
		if (!buffer->pages)
			goto unmap_dma;
>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance

		for_each_sg(table->sgl, sg, table->nents, i) {
			struct page *page = sg_page(sg);

			for (j = 0; j < sg->length / PAGE_SIZE; j++)
				buffer->pages[k++] = page++;
		}

		if (ret)
			goto err;
	}

<<<<<<< HEAD
	mutex_init(&buffer->lock);
	/* this will set up dma addresses for the sglist -- it is not
	   technically correct as per the dma api -- a specific
	   device isn't really taking ownership here.  However, in practice on
	   our systems the only dma_address space is physical addresses.
	   Additionally, we can't afford the overhead of invalidating every
	   allocation via dma_map_sg. The implicit contract here is that
	   memory coming from the heaps is ready for dma, ie if it has a
	   cached mapping that mapping has been invalidated */
=======
>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance
	for_each_sg(buffer->sg_table->sgl, sg, buffer->sg_table->nents, i) {
		if (sg_dma_address(sg) == 0)
			sg_dma_address(sg) = sg_phys(sg);
	}

	return buffer;

unmap_dma:
	heap->ops->unmap_dma(heap, buffer);
<<<<<<< HEAD
	heap->ops->free(buffer);
err1:
	if (buffer->pages)
		vfree(buffer->pages);
err2:
=======
free_heap:
	heap->ops->free(buffer);
free_buffer:
>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance
	kfree(buffer);
	return ERR_PTR(-EINVAL);
}

void ion_buffer_destroy(struct ion_buffer *buffer)
{
	if (buffer->kmap_cnt > 0)
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
	buffer->heap->ops->unmap_dma(buffer->heap, buffer);
	buffer->heap->ops->free(buffer);
<<<<<<< HEAD
	if (buffer->pages)
=======
	if (ion_buffer_fault_user_mappings(buffer))
>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance
		vfree(buffer->pages);
	kfree(buffer);
}

static void ion_buffer_kref_destroy(struct kref *kref)
{
	struct ion_buffer *buffer = container_of(kref, typeof(*buffer), ref);
	struct ion_heap *heap = buffer->heap;

	msm_dma_buf_freed(buffer);

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_freelist_add(heap, buffer);
	else
		ion_buffer_destroy(buffer);
}

static struct ion_handle *ion_handle_create(struct ion_client *client,
					    struct ion_buffer *buffer)
{
	struct ion_handle *handle;

	handle = kmalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return ERR_PTR(-ENOMEM);

	*handle = (typeof(*handle)){
		.buffer = buffer,
		.client = client,
		.kmap_cnt = ATOMIC_INIT(0),
		.refcount = ATOMIC_INIT(1)
	};

	return handle;
}

static void *ion_buffer_kmap_get(struct ion_buffer *buffer)
{
	void *vaddr;

	mutex_lock(&buffer->kmap_lock);
	if (buffer->kmap_cnt) {
		vaddr = buffer->vaddr;
		buffer->kmap_cnt++;
	} else {
		vaddr = buffer->heap->ops->map_kernel(buffer->heap, buffer);
		if (IS_ERR_OR_NULL(vaddr)) {
			vaddr = ERR_PTR(-EINVAL);
		} else {
			buffer->vaddr = vaddr;
			buffer->kmap_cnt++;
		}
	}
	mutex_unlock(&buffer->kmap_lock);

	return vaddr;
}

static void ion_buffer_kmap_put(struct ion_buffer *buffer)
{
	mutex_lock(&buffer->kmap_lock);
	if (!--buffer->kmap_cnt)
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
	mutex_unlock(&buffer->kmap_lock);
}

static void *ion_handle_kmap_get(struct ion_handle *handle)
{
	struct ion_buffer *buffer = handle->buffer;
	void *objp;

	objp = ion_buffer_kmap_get(buffer);
	if (!IS_ERR(objp))
		atomic_inc(&handle->kmap_cnt);

	return objp;
}

static void ion_handle_kmap_put(struct ion_handle *handle)
{
	struct ion_buffer *buffer = handle->buffer;

	if (atomic_add_unless(&handle->kmap_cnt, -1, 0))
		ion_buffer_kmap_put(buffer);
}

static void ion_handle_get(struct ion_handle *handle)
{
	atomic_inc(&handle->refcount);
}

bool ion_handle_validate(struct ion_client *client, struct ion_handle *handle)
{
	bool found;

	read_lock(&client->idr_lock);
	found = idr_find(&client->idr, handle->id) == handle;
	read_unlock(&client->idr_lock);

	return found;
}

void *ion_map_kernel(struct ion_client *client, struct ion_handle *handle)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return ERR_PTR(-EINVAL);

	buffer = handle->buffer;
	if (!buffer->heap->ops->map_kernel)
		return ERR_PTR(-ENODEV);

	return ion_handle_kmap_get(handle);
}

void ion_unmap_kernel(struct ion_client *client, struct ion_handle *handle)
{
	if (ion_handle_validate(client, handle))
		ion_handle_kmap_put(handle);
}

void ion_handle_put(struct ion_handle *handle)
{
	struct ion_client *client = handle->client;
	struct ion_buffer *buffer = handle->buffer;

	if (atomic_dec_return(&handle->refcount))
		return;

	write_lock(&client->idr_lock);
	idr_remove(&client->idr, handle->id);
	write_unlock(&client->idr_lock);

	write_lock(&client->rb_lock);
	rb_erase(&handle->node, &client->handles);
	write_unlock(&client->rb_lock);

	ion_handle_kmap_put(handle);
	kref_put(&buffer->ref, ion_buffer_kref_destroy);
	kfree(handle);
}

static struct ion_handle *ion_handle_lookup_get(struct ion_client *client,
						struct ion_buffer *buffer)
{
	struct rb_node **p = &client->handles.rb_node;
	struct ion_handle *entry;

	read_lock(&client->rb_lock);
	while (*p) {
		entry = rb_entry(*p, typeof(*entry), node);
		if (buffer < entry->buffer) {
			p = &(*p)->rb_left;
		} else if (buffer > entry->buffer) {
			p = &(*p)->rb_right;
		} else {
			read_unlock(&client->rb_lock);
			ion_handle_get(entry);
			return entry;
		}
	}
	read_unlock(&client->rb_lock);

	return ERR_PTR(-EINVAL);
}

struct ion_handle *ion_handle_find_by_id(struct ion_client *client, int id)
{
	struct ion_handle *handle;

	read_lock(&client->idr_lock);
	handle = idr_find(&client->idr, id);
	read_unlock(&client->idr_lock);

	return handle ? handle : ERR_PTR(-EINVAL);
}

static int ion_handle_add(struct ion_client *client, struct ion_handle *handle)
{
	struct rb_node **p = &client->handles.rb_node;
	struct ion_buffer *buffer = handle->buffer;
	struct rb_node *parent = NULL;
	struct ion_handle *entry;
	int id;

	idr_preload(GFP_KERNEL);
	write_lock(&client->idr_lock);
	id = idr_alloc(&client->idr, handle, 1, 0, GFP_NOWAIT);
	write_unlock(&client->idr_lock);
	idr_preload_end();

	if (id < 0)
		return id;

	handle->id = id;

	write_lock(&client->rb_lock);
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, typeof(*entry), node);
		if (buffer < entry->buffer)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	rb_link_node(&handle->node, parent, p);
	rb_insert_color(&handle->node, &client->handles);
	write_unlock(&client->rb_lock);

	return 0;
}

struct ion_handle *ion_alloc(struct ion_client *client, size_t len,
			     size_t align, unsigned int heap_id_mask,
			     unsigned int flags)
{
	struct ion_device *dev = client->dev;
	struct ion_buffer *buffer = NULL;
	struct ion_handle *handle;
	struct ion_heap *heap;

	len = PAGE_ALIGN(len);
	if (!len)
		return ERR_PTR(-EINVAL);

	flags |= ION_FLAG_CACHED_NEEDS_SYNC;

	down_read(&dev->heap_lock);
	plist_for_each_entry(heap, &dev->heaps, node) {
		if (!(BIT(heap->id) & heap_id_mask))
			continue;

		buffer = ion_buffer_create(heap, dev, len, align, flags);
		if (!IS_ERR(buffer))
			break;
	}
	up_read(&dev->heap_lock);

	if (IS_ERR_OR_NULL(buffer))
		return ERR_PTR(-EINVAL);

	handle = ion_handle_create(client, buffer);
	if (IS_ERR(handle)) {
		kref_put(&buffer->ref, ion_buffer_kref_destroy);
		return ERR_PTR(-EINVAL);
	}

	if (ion_handle_add(client, handle)) {
		/* ion_handle_put will put the buffer as well */
		ion_handle_put(handle);
		return ERR_PTR(-EINVAL);
	}

	return handle;
}

void ion_free(struct ion_client *client, struct ion_handle *handle)
{
	if (ion_handle_validate(client, handle))
		ion_handle_put(handle);
}

int ion_phys(struct ion_client *client, struct ion_handle *handle,
	     ion_phys_addr_t *addr, size_t *len)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return -EINVAL;

	buffer = handle->buffer;
	if (!buffer->heap->ops->phys)
		return -ENODEV;

	return buffer->heap->ops->phys(buffer->heap, buffer, addr, len);
}

struct ion_client *ion_client_create(struct ion_device *dev)
{
	struct ion_client *client;

	client = kmalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);

	*client = (typeof(*client)){
		.dev = dev,
		.handles = RB_ROOT,
		.idr = IDR_INIT(client->idr),
		.idr_lock = __RW_LOCK_UNLOCKED(client->idr_lock),
		.rb_lock = __RW_LOCK_UNLOCKED(client->rb_lock)
	};

	return client;
}

void ion_client_destroy(struct ion_client *client)
{
	struct ion_handle *handle;
	struct rb_node *n;

	while ((n = rb_first(&client->handles))) {
		handle = rb_entry(n, typeof(*handle), node);
		ion_handle_put(handle);
	}

	idr_destroy(&client->idr);
	kfree(client);
}

int ion_handle_get_flags(struct ion_client *client, struct ion_handle *handle,
			 unsigned long *flags)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return -EINVAL;

	buffer = handle->buffer;
	*flags = buffer->flags;
	return 0;
}

int ion_handle_get_size(struct ion_client *client, struct ion_handle *handle,
			size_t *size)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return -EINVAL;

	buffer = handle->buffer;
	*size = buffer->size;
	return 0;
}

struct sg_table *ion_sg_table(struct ion_client *client,
			      struct ion_handle *handle)
{
	struct ion_buffer *buffer;
	struct sg_table *table;

	if (!ion_handle_validate(client, handle))
		return ERR_PTR(-EINVAL);

	buffer = handle->buffer;
	table = buffer->sg_table;
	return table;
}

static struct scatterlist *ion_sg_alloc(unsigned int nents, gfp_t gfp_mask)
{
	if (nents == SG_MAX_SINGLE_ALLOC)
		return kmem_cache_alloc(ion_page_pool, gfp_mask);

	return kmalloc(nents * sizeof(struct scatterlist), gfp_mask);
}

static void ion_sg_free(struct scatterlist *sg, unsigned int nents)
{
	if (nents == SG_MAX_SINGLE_ALLOC)
		kmem_cache_free(ion_page_pool, sg);
	else
		kfree(sg);
}

static int ion_sg_alloc_table(struct sg_table *table, unsigned int nents,
			      gfp_t gfp_mask)
{
	return __sg_alloc_table(table, nents, SG_MAX_SINGLE_ALLOC, NULL,
				gfp_mask, ion_sg_alloc);
}

static void ion_sg_free_table(struct sg_table *table)
{
<<<<<<< HEAD
	struct ion_buffer *buffer;
	void *vaddr;

	mutex_lock(&client->lock);
	if (!ion_handle_validate(client, handle)) {
		pr_err("%s: invalid handle passed to map_kernel.\n",
		       __func__);
		mutex_unlock(&client->lock);
		return ERR_PTR(-EINVAL);
	}

	buffer = handle->buffer;

	if (!handle->buffer->heap->ops->map_kernel) {
		pr_err("%s: map_kernel is not implemented by this heap.\n",
		       __func__);
		mutex_unlock(&client->lock);
		return ERR_PTR(-ENODEV);
	}

	mutex_lock(&buffer->lock);
	vaddr = ion_handle_kmap_get(handle);
	mutex_unlock(&buffer->lock);
	mutex_unlock(&client->lock);
	return vaddr;
}
EXPORT_SYMBOL(ion_map_kernel);

void ion_unmap_kernel(struct ion_client *client, struct ion_handle *handle)
{
	struct ion_buffer *buffer;

	mutex_lock(&client->lock);
	buffer = handle->buffer;
	mutex_lock(&buffer->lock);
	ion_handle_kmap_put(handle);
	mutex_unlock(&buffer->lock);
	mutex_unlock(&client->lock);
}
EXPORT_SYMBOL(ion_unmap_kernel);

static int ion_debug_client_show(struct seq_file *s, void *unused)
{
	struct ion_client *client = s->private;
	struct rb_node *n, *cnode;
	bool found = false;

	down_write(&ion_dev->lock);

	if (!client || (client->dev != ion_dev)) {
		up_write(&ion_dev->lock);
		return -EINVAL;
	}

	cnode = rb_first(&ion_dev->clients);
	for ( ; cnode; cnode = rb_next(cnode)) {
		struct ion_client *c = rb_entry(cnode,
				struct ion_client, node);
		if (client == c) {
			found = true;
			break;
		}
	}

	if (!found) {
		up_write(&ion_dev->lock);
		return -EINVAL;
	}

	seq_printf(s, "%16.16s: %16.16s : %16.16s : %12.12s\n",
			"heap_name", "size_in_bytes", "handle refcount",
			"buffer");

	mutex_lock(&client->lock);
	for (n = rb_first(&client->handles); n; n = rb_next(n)) {
		struct ion_handle *handle = rb_entry(n, struct ion_handle,
						     node);

		seq_printf(s, "%16.16s: %16zx : %16d : %12pK",
				handle->buffer->heap->name,
				handle->buffer->size,
				atomic_read(&handle->ref.refcount),
				handle->buffer);

		seq_printf(s, "\n");
	}
	mutex_unlock(&client->lock);
	up_write(&ion_dev->lock);
	return 0;
}

static int ion_debug_client_open(struct inode *inode, struct file *file)
{
	return single_open(file, ion_debug_client_show, inode->i_private);
}

static const struct file_operations debug_client_fops = {
	.open = ion_debug_client_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int ion_get_client_serial(const struct rb_root *root,
					const unsigned char *name)
{
	int serial = -1;
	struct rb_node *node;

	for (node = rb_first(root); node; node = rb_next(node)) {
		struct ion_client *client = rb_entry(node, struct ion_client,
						node);

		if (strcmp(client->name, name))
			continue;
		serial = max(serial, client->display_serial);
	}
	return serial + 1;
}

struct ion_client *ion_client_create(struct ion_device *dev,
				     const char *name)
{
	struct ion_client *client;
	struct task_struct *task;
	struct rb_node **p;
	struct rb_node *parent = NULL;
	struct ion_client *entry;
	pid_t pid;

	if (!name) {
		pr_err("%s: Name cannot be null\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	get_task_struct(current->group_leader);
	task_lock(current->group_leader);
	pid = task_pid_nr(current->group_leader);
	/* don't bother to store task struct for kernel threads,
	   they can't be killed anyway */
	if (current->group_leader->flags & PF_KTHREAD) {
		put_task_struct(current->group_leader);
		task = NULL;
	} else {
		task = current->group_leader;
	}
	task_unlock(current->group_leader);

	client = kzalloc(sizeof(struct ion_client), GFP_KERNEL);
	if (!client)
		goto err_put_task_struct;

	client->dev = dev;
	client->handles = RB_ROOT;
	idr_init(&client->idr);
	mutex_init(&client->lock);

	client->task = task;
	client->pid = pid;
	client->name = kstrdup(name, GFP_KERNEL);
	if (!client->name)
		goto err_free_client;

	down_write(&dev->lock);
	client->display_serial = ion_get_client_serial(&dev->clients, name);
	client->display_name = kasprintf(
		GFP_KERNEL, "%s-%d", name, client->display_serial);
	if (!client->display_name) {
		up_write(&dev->lock);
		goto err_free_client_name;
	}
	p = &dev->clients.rb_node;
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct ion_client, node);

		if (client < entry)
			p = &(*p)->rb_left;
		else if (client > entry)
			p = &(*p)->rb_right;
	}
	rb_link_node(&client->node, parent, p);
	rb_insert_color(&client->node, &dev->clients);

	client->debug_root = debugfs_create_file(client->display_name, 0664,
						dev->clients_debug_root,
						client, &debug_client_fops);
	if (!client->debug_root) {
		char buf[256], *path;

		path = dentry_path(dev->clients_debug_root, buf, 256);
		pr_err("Failed to create client debugfs at %s/%s\n",
			path, client->display_name);
	}

	up_write(&dev->lock);

	return client;

err_free_client_name:
	kfree(client->name);
err_free_client:
	kfree(client);
err_put_task_struct:
	if (task)
		put_task_struct(current->group_leader);
	return ERR_PTR(-ENOMEM);
}
EXPORT_SYMBOL(ion_client_create);

void ion_client_destroy(struct ion_client *client)
{
	struct ion_device *dev = client->dev;
	struct rb_node *n;

	pr_debug("%s: %d\n", __func__, __LINE__);
	mutex_lock(&client->lock);
	while ((n = rb_first(&client->handles))) {
		struct ion_handle *handle = rb_entry(n, struct ion_handle,
						     node);
		ion_handle_destroy(&handle->ref);
	}

	idr_destroy(&client->idr);
	mutex_unlock(&client->lock);

	down_write(&dev->lock);
	if (client->task)
		put_task_struct(client->task);
	rb_erase(&client->node, &dev->clients);
	debugfs_remove_recursive(client->debug_root);

	up_write(&dev->lock);

	kfree(client->display_name);
	kfree(client->name);
	kfree(client);
}
EXPORT_SYMBOL(ion_client_destroy);

int ion_handle_get_flags(struct ion_client *client, struct ion_handle *handle,
			unsigned long *flags)
{
	struct ion_buffer *buffer;

	mutex_lock(&client->lock);
	if (!ion_handle_validate(client, handle)) {
		pr_err("%s: invalid handle passed to %s.\n",
		       __func__, __func__);
		mutex_unlock(&client->lock);
		return -EINVAL;
	}
	buffer = handle->buffer;
	mutex_lock(&buffer->lock);
	*flags = buffer->flags;
	mutex_unlock(&buffer->lock);
	mutex_unlock(&client->lock);

	return 0;
}
EXPORT_SYMBOL(ion_handle_get_flags);

int ion_handle_get_size(struct ion_client *client, struct ion_handle *handle,
			size_t *size)
{
	struct ion_buffer *buffer;

	mutex_lock(&client->lock);
	if (!ion_handle_validate(client, handle)) {
		pr_err("%s: invalid handle passed to %s.\n",
		       __func__, __func__);
		mutex_unlock(&client->lock);
		return -EINVAL;
	}
	buffer = handle->buffer;
	mutex_lock(&buffer->lock);
	*size = buffer->size;
	mutex_unlock(&buffer->lock);
	mutex_unlock(&client->lock);

	return 0;
}
EXPORT_SYMBOL(ion_handle_get_size);

/**
 * ion_sg_table - get an sg_table for the buffer
 *
 * NOTE: most likely you should NOT being using this API.
 * You should be using Ion as a DMA Buf exporter and using
 * the sg_table returned by dma_buf_map_attachment.
 */
struct sg_table *ion_sg_table(struct ion_client *client,
			      struct ion_handle *handle)
{
	struct ion_buffer *buffer;
	struct sg_table *table;

	mutex_lock(&client->lock);
	if (!ion_handle_validate(client, handle)) {
		pr_err("%s: invalid handle passed to map_dma.\n",
		       __func__);
		mutex_unlock(&client->lock);
		return ERR_PTR(-EINVAL);
	}
	buffer = handle->buffer;
	table = buffer->sg_table;
	mutex_unlock(&client->lock);
	return table;
}
EXPORT_SYMBOL(ion_sg_table);
=======
	__sg_free_table(table, SG_MAX_SINGLE_ALLOC, false, ion_sg_free);
}
>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance

struct sg_table *ion_create_chunked_sg_table(phys_addr_t buffer_base,
					     size_t chunk_size,
					     size_t total_size)
{
	struct scatterlist *sg;
	struct sg_table *table;
	int i, n_chunks, ret;

	table = kmem_cache_alloc(ion_sg_table_pool, GFP_KERNEL);
	if (!table)
		return ERR_PTR(-ENOMEM);

	n_chunks = DIV_ROUND_UP(total_size, chunk_size);
	ret = ion_sg_alloc_table(table, n_chunks, GFP_KERNEL);
	if (ret)
		goto free_table;

	for_each_sg(table->sgl, sg, table->nents, i) {
		sg_dma_address(sg) = buffer_base + i * chunk_size;
		sg->length = chunk_size;
	}

	return table;

free_table:
	kmem_cache_free(ion_sg_table_pool, table);
	return ERR_PTR(ret);
}

static struct sg_table *ion_dupe_sg_table(struct sg_table *orig_table)
{
	struct scatterlist *sg, *sg_orig;
	struct sg_table *table;
	int i, ret;

	table = kmem_cache_alloc(ion_sg_table_pool, GFP_KERNEL);
	if (!table)
		return NULL;

	ret = ion_sg_alloc_table(table, orig_table->nents, GFP_KERNEL);
	if (ret) {
		kmem_cache_free(ion_sg_table_pool, table);
		return NULL;
	}

	sg_orig = orig_table->sgl;
	for_each_sg(table->sgl, sg, table->nents, i) {
		*sg = *sg_orig;
		sg_orig = sg_next(sg_orig);
	}

	return table;
}

void ion_pages_sync_for_device(struct device *dev, struct page *page,
			       size_t size, enum dma_data_direction dir)
{
	struct scatterlist sg;

	sg_init_table(&sg, 1);
	sg_set_page(&sg, page, size, 0);
	sg_dma_address(&sg) = page_to_phys(page);
	dma_sync_sg_for_device(dev, &sg, 1, dir);
}

static void ion_buffer_sync_for_device(struct ion_buffer *buffer,
				       struct device *dev,
				       enum dma_data_direction dir)
{
	struct ion_vma_list *vma_list;
	int i, pages;

	if (!ion_buffer_fault_user_mappings(buffer))
		return;

	pages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
	mutex_lock(&buffer->page_lock);
	for (i = 0; i < pages; i++) {
		struct page *page = buffer->pages[i];

		if (ion_buffer_page_is_dirty(page))
			ion_pages_sync_for_device(dev, ion_buffer_page(page),
						  PAGE_SIZE, dir);

		ion_buffer_page_clean(buffer->pages + i);
	}
	mutex_unlock(&buffer->page_lock);

	mutex_lock(&buffer->vma_lock);
	list_for_each_entry(vma_list, &buffer->vmas, list) {
		struct vm_area_struct *vma = vma_list->vma;

		zap_page_range(vma, vma->vm_start, vma->vm_end - vma->vm_start,
			       NULL);
	}
	mutex_unlock(&buffer->vma_lock);
}

static struct sg_table *ion_map_dma_buf(struct dma_buf_attachment *attachment,
					enum dma_data_direction direction)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = dmabuf->priv;
	struct sg_table *table;

	table = ion_dupe_sg_table(buffer->sg_table);
	if (!table)
		return NULL;

	ion_buffer_sync_for_device(buffer, attachment->dev, direction);
	return table;
}

static void ion_unmap_dma_buf(struct dma_buf_attachment *attachment,
			      struct sg_table *table,
			      enum dma_data_direction direction)
{
	ion_sg_free_table(table);
	kmem_cache_free(ion_sg_table_pool, table);
}

static int ion_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	unsigned long pfn;
	int ret;

	mutex_lock(&buffer->page_lock);
	ion_buffer_page_dirty(buffer->pages + vmf->pgoff);
	pfn = page_to_pfn(ion_buffer_page(buffer->pages[vmf->pgoff]));
	ret = vm_insert_pfn(vma, (unsigned long)vmf->virtual_address, pfn);
	mutex_unlock(&buffer->page_lock);

	return ret ? VM_FAULT_ERROR : VM_FAULT_NOPAGE;
}

static void ion_vm_open(struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	struct ion_vma_list *vma_list;

	vma_list = kmalloc(sizeof(*vma_list), GFP_KERNEL);
	if (!vma_list)
		return;

	vma_list->vma = vma;

	mutex_lock(&buffer->vma_lock);
	list_add(&vma_list->list, &buffer->vmas);
	mutex_unlock(&buffer->vma_lock);
}

static void ion_vm_close(struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	struct ion_vma_list *vma_list;

	mutex_lock(&buffer->vma_lock);
	list_for_each_entry(vma_list, &buffer->vmas, list) {
		if (vma_list->vma == vma) {
			list_del(&vma_list->list);
			break;
		}
	}
	mutex_unlock(&buffer->vma_lock);

	if (buffer->heap->ops->unmap_user)
		buffer->heap->ops->unmap_user(buffer->heap, buffer);

	kfree(vma_list);
}

static struct vm_operations_struct ion_vma_ops = {
	.open = ion_vm_open,
	.close = ion_vm_close,
	.fault = ion_vm_fault
};

static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = dmabuf->priv;

	if (!buffer->heap->ops->map_user)
		return -EINVAL;

	if (ion_buffer_fault_user_mappings(buffer)) {
		vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND |
				 VM_DONTDUMP | VM_MIXEDMAP;
		vma->vm_private_data = buffer;
		vma->vm_ops = &ion_vma_ops;
		ion_vm_open(vma);
		return 0;
	}

	if (!(buffer->flags & ION_FLAG_CACHED))
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return buffer->heap->ops->map_user(buffer->heap, buffer, vma);
}

static void ion_dma_buf_release(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = dmabuf->priv;

	kref_put(&buffer->ref, ion_buffer_kref_destroy);
}

static void *ion_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	struct ion_buffer *buffer = dmabuf->priv;

	return buffer->vaddr + offset * PAGE_SIZE;
}

static int ion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf, size_t start,
					size_t len,
					enum dma_data_direction direction)
{
	struct ion_buffer *buffer = dmabuf->priv;

	if (!buffer->heap->ops->map_kernel)
		return -ENODEV;

	return PTR_RET(ion_buffer_kmap_get(buffer));
}

static void ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf, size_t start,
				       size_t len,
				       enum dma_data_direction direction)
{
	struct ion_buffer *buffer = dmabuf->priv;

	ion_buffer_kmap_put(buffer);
}

static const struct dma_buf_ops dma_buf_ops = {
	.map_dma_buf = ion_map_dma_buf,
	.unmap_dma_buf = ion_unmap_dma_buf,
	.mmap = ion_mmap,
	.release = ion_dma_buf_release,
	.begin_cpu_access = ion_dma_buf_begin_cpu_access,
	.end_cpu_access = ion_dma_buf_end_cpu_access,
	.kmap_atomic = ion_dma_buf_kmap,
	.kmap = ion_dma_buf_kmap
};

struct dma_buf *ion_share_dma_buf(struct ion_client *client,
				  struct ion_handle *handle)
{
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;

	if (!ion_handle_validate(client, handle))
		return ERR_PTR(-EINVAL);

	buffer = handle->buffer;

<<<<<<< HEAD
	dmabuf = dma_buf_export(buffer, &dma_buf_ops, buffer->size, O_RDWR,
				NULL);
	if (IS_ERR(dmabuf)) {
		ion_buffer_put(buffer);
		return dmabuf;
	}
=======
	exp_info.ops = &dma_buf_ops;
	exp_info.size = buffer->size;
	exp_info.flags = O_RDWR;
	exp_info.priv = buffer;

	dmabuf = dma_buf_export(&exp_info);
	if (!IS_ERR(dmabuf))
		kref_get(&buffer->ref);
>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance

	return dmabuf;
}

int ion_share_dma_buf_fd(struct ion_client *client, struct ion_handle *handle)
{
	struct dma_buf *dmabuf;
	int fd;

	dmabuf = ion_share_dma_buf(client, handle);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

	return fd;
}

struct ion_handle *ion_import_dma_buf(struct ion_client *client, int fd)
{
	struct ion_buffer *buffer;
	struct ion_handle *handle;
	struct dma_buf *dmabuf;
	int ret;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return ERR_CAST(dmabuf);

	if (dmabuf->ops != &dma_buf_ops)
		goto put_dmabuf;

	buffer = dmabuf->priv;
	handle = ion_handle_lookup_get(client, buffer);
	if (IS_ERR(handle)) {
		handle = ion_handle_create(client, buffer);
		if (IS_ERR(handle))
			goto put_dmabuf;

		kref_get(&buffer->ref);
		ret = ion_handle_add(client, handle);
		if (ret)
			goto put_handle;
	}

	dma_buf_put(dmabuf);
	return handle;

put_handle:
	/* ion_handle_put will put the buffer as well */
	ion_handle_put(handle);
put_dmabuf:
	dma_buf_put(dmabuf);
	return ERR_PTR(-EINVAL);
}

static int ion_sync_for_device(struct ion_client *client, int fd)
{
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	if (dmabuf->ops != &dma_buf_ops)
		goto put_dmabuf;

	buffer = dmabuf->priv;
	dma_sync_sg_for_device(NULL, buffer->sg_table->sgl,
			       buffer->sg_table->nents, DMA_BIDIRECTIONAL);
	dma_buf_put(dmabuf);
	return 0;

put_dmabuf:
	dma_buf_put(dmabuf);
	return -EINVAL;
}

static long ion_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	union {
		struct ion_fd_data fd;
		struct ion_allocation_data allocation;
		struct ion_handle_data handle;
		struct ion_custom_data custom;
	} data;
	struct ion_client *client = file->private_data;
	struct ion_device *dev = client->dev;
	struct ion_handle *handle;

	if (_IOC_SIZE(cmd) > sizeof(data))
		return -EINVAL;

	switch (cmd) {
	case ION_IOC_ALLOC:
	case ION_IOC_FREE:
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	case ION_IOC_IMPORT:
	case ION_IOC_SYNC:
	case ION_IOC_CUSTOM:
		if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;
		break;
	}

	switch (cmd) {
	case ION_IOC_ALLOC:
		handle = ion_alloc(client, data.allocation.len,
				   data.allocation.align,
				   data.allocation.heap_id_mask,
				   data.allocation.flags);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.allocation.handle = handle->id;
		break;
	case ION_IOC_FREE:
		handle = ion_handle_find_by_id(client, data.handle.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		ion_handle_put(handle);
		break;
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
		handle = ion_handle_find_by_id(client, data.handle.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.fd.fd = ion_share_dma_buf_fd(client, handle);
		if (data.fd.fd < 0)
			return data.fd.fd;
		break;
	case ION_IOC_IMPORT:
		handle = ion_import_dma_buf(client, data.fd.fd);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.handle.handle = handle->id;
		break;
	case ION_IOC_SYNC:
		return ion_sync_for_device(client, data.fd.fd);
	case ION_IOC_CUSTOM:
		if (dev->custom_ioctl)
			return dev->custom_ioctl(client, data.custom.cmd,
						 data.custom.arg);
		return -ENOTTY;
	case ION_IOC_CLEAN_CACHES:
	case ION_IOC_INV_CACHES:
	case ION_IOC_CLEAN_INV_CACHES:
		return client->dev->custom_ioctl(client, cmd, arg);
	default:
		return -ENOTTY;
	}

	switch (cmd) {
	case ION_IOC_ALLOC:
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	case ION_IOC_IMPORT:
		if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd))) {
			if (cmd == ION_IOC_ALLOC)
				ion_handle_put(handle);
			return -EFAULT;
		}
		break;
	}

	return 0;
}

static int ion_release(struct inode *inode, struct file *file)
{
	struct ion_client *client = file->private_data;

	ion_client_destroy(client);
	return 0;
}

static int ion_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
	struct ion_device *dev = container_of(miscdev, typeof(*dev), dev);
	struct ion_client *client;

	client = ion_client_create(dev);
	if (IS_ERR(client))
		return PTR_ERR(client);

	file->private_data = client;
	return 0;
}

static const struct file_operations ion_fops = {
	.owner = THIS_MODULE,
	.open = ion_open,
	.release = ion_release,
	.unlocked_ioctl = ion_ioctl,
	.compat_ioctl = compat_ion_ioctl
};

<<<<<<< HEAD
static size_t ion_debug_heap_total(struct ion_client *client,
				   unsigned int id)
{
	size_t size = 0;
	struct rb_node *n;

	mutex_lock(&client->lock);
	for (n = rb_first(&client->handles); n; n = rb_next(n)) {
		struct ion_handle *handle = rb_entry(n,
						     struct ion_handle,
						     node);
		if (handle->buffer->heap->id == id)
			size += handle->buffer->size;
	}
	mutex_unlock(&client->lock);
	return size;
}

/**
 * Create a mem_map of the heap.
 * @param s seq_file to log error message to.
 * @param heap The heap to create mem_map for.
 * @param mem_map The mem map to be created.
 */
void ion_debug_mem_map_create(struct seq_file *s, struct ion_heap *heap,
			      struct list_head *mem_map)
{
	struct ion_device *dev = heap->dev;
	struct rb_node *cnode;
	size_t size;
	struct ion_client *client;

	if (!heap->ops->phys)
		return;

	down_read(&dev->lock);
	for (cnode = rb_first(&dev->clients); cnode; cnode = rb_next(cnode)) {
		struct rb_node *hnode;
		client = rb_entry(cnode, struct ion_client, node);

		mutex_lock(&client->lock);
		for (hnode = rb_first(&client->handles);
		     hnode;
		     hnode = rb_next(hnode)) {
			struct ion_handle *handle = rb_entry(
				hnode, struct ion_handle, node);
			if (handle->buffer->heap == heap) {
				struct mem_map_data *data =
					kzalloc(sizeof(*data), GFP_KERNEL);
				if (!data)
					goto inner_error;
				heap->ops->phys(heap, handle->buffer,
							&(data->addr), &size);
				data->size = (unsigned long) size;
				data->addr_end = data->addr + data->size - 1;
				data->client_name = kstrdup(client->name,
							GFP_KERNEL);
				if (!data->client_name) {
					kfree(data);
					goto inner_error;
				}
				list_add(&data->node, mem_map);
			}
		}
		mutex_unlock(&client->lock);
	}
	up_read(&dev->lock);
	return;

inner_error:
	seq_puts(s,
		"ERROR: out of memory. Part of memory map will not be logged\n");
	mutex_unlock(&client->lock);
	up_read(&dev->lock);
}

/**
 * Free the memory allocated by ion_debug_mem_map_create
 * @param mem_map The mem map to free.
 */
static void ion_debug_mem_map_destroy(struct list_head *mem_map)
{
	if (mem_map) {
		struct mem_map_data *data, *tmp;
		list_for_each_entry_safe(data, tmp, mem_map, node) {
			list_del(&data->node);
			kfree(data->client_name);
			kfree(data);
		}
	}
}

static int mem_map_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct mem_map_data *d1, *d2;
	d1 = list_entry(a, struct mem_map_data, node);
	d2 = list_entry(b, struct mem_map_data, node);
	if (d1->addr == d2->addr)
		return d1->size - d2->size;
	return d1->addr - d2->addr;
}

/**
 * Print heap debug information.
 * @param s seq_file to log message to.
 * @param heap pointer to heap that we will print debug information for.
 */
static void ion_heap_print_debug(struct seq_file *s, struct ion_heap *heap)
{
	if (heap->ops->print_debug) {
		struct list_head mem_map = LIST_HEAD_INIT(mem_map);
		ion_debug_mem_map_create(s, heap, &mem_map);
		list_sort(NULL, &mem_map, mem_map_cmp);
		heap->ops->print_debug(heap, s, &mem_map);
		ion_debug_mem_map_destroy(&mem_map);
	}
}

static int ion_debug_heap_show(struct seq_file *s, void *unused)
{
	struct ion_heap *heap = s->private;
	struct ion_device *dev = heap->dev;
	struct rb_node *n;
	size_t total_size = 0;
	size_t total_orphaned_size = 0;

	seq_printf(s, "%16.s %16.s %16.s\n", "client", "pid", "size");
	seq_puts(s, "----------------------------------------------------\n");

	down_read(&dev->lock);
	for (n = rb_first(&dev->clients); n; n = rb_next(n)) {
		struct ion_client *client = rb_entry(n, struct ion_client,
						     node);
		size_t size = ion_debug_heap_total(client, heap->id);

		if (!size)
			continue;
		if (client->task) {
			char task_comm[TASK_COMM_LEN];

			get_task_comm(task_comm, client->task);
			seq_printf(s, "%16.s %16u %16zu\n", task_comm,
				   client->pid, size);
		} else {
			seq_printf(s, "%16.s %16u %16zu\n", client->name,
				   client->pid, size);
		}
	}
	up_read(&dev->lock);
	seq_puts(s, "----------------------------------------------------\n");
	seq_puts(s, "orphaned allocations (info is from last known client):\n");
	mutex_lock(&dev->buffer_lock);
	for (n = rb_first(&dev->buffers); n; n = rb_next(n)) {
		struct ion_buffer *buffer = rb_entry(n, struct ion_buffer,
						     node);
		if (buffer->heap->id != heap->id)
			continue;
		total_size += buffer->size;
		if (!buffer->handle_count) {
			seq_printf(s, "%16.s %16u %16zu %d %d\n",
				   buffer->task_comm, buffer->pid,
				   buffer->size, buffer->kmap_cnt,
				   atomic_read(&buffer->ref.refcount));
			total_orphaned_size += buffer->size;
		}
	}
	mutex_unlock(&dev->buffer_lock);
	seq_puts(s, "----------------------------------------------------\n");
	seq_printf(s, "%16.s %16zu\n", "total orphaned",
		   total_orphaned_size);
	seq_printf(s, "%16.s %16zu\n", "total ", total_size);
	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		seq_printf(s, "%16.s %16zu\n", "deferred free",
				heap->free_list_size);
	seq_puts(s, "----------------------------------------------------\n");

	if (heap->debug_show)
		heap->debug_show(heap, s, unused);

	ion_heap_print_debug(s, heap);
	return 0;
}

static int ion_debug_heap_open(struct inode *inode, struct file *file)
{
	return single_open(file, ion_debug_heap_show, inode->i_private);
}

static const struct file_operations debug_heap_fops = {
	.open = ion_debug_heap_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

void show_ion_usage(struct ion_device *dev)
{
	struct ion_heap *heap;

	if (!down_read_trylock(&dev->lock)) {
		pr_err("Ion output would deadlock, can't print debug information\n");
		return;
	}

	pr_info("%16.s %16.s %16.s\n", "Heap name", "Total heap size",
					"Total orphaned size");
	pr_info("---------------------------------\n");
	plist_for_each_entry(heap, &dev->heaps, node) {
		pr_info("%16.s 0x%16.x 0x%16.x\n",
			heap->name, atomic_read(&heap->total_allocated),
			atomic_read(&heap->total_allocated) -
			atomic_read(&heap->total_handles));
		if (heap->debug_show)
			heap->debug_show(heap, NULL, 0);

	}
	up_read(&dev->lock);
}

#ifdef DEBUG_HEAP_SHRINKER
static int debug_shrink_set(void *data, u64 val)
{
	struct ion_heap *heap = data;
	struct shrink_control sc;
	int objs;

	sc.gfp_mask = -1;
	sc.nr_to_scan = val;

	if (!val) {
		objs = heap->shrinker.count_objects(&heap->shrinker, &sc);
		sc.nr_to_scan = objs;
	}

	heap->shrinker.scan_objects(&heap->shrinker, &sc);
	return 0;
}

static int debug_shrink_get(void *data, u64 *val)
{
	struct ion_heap *heap = data;
	struct shrink_control sc;
	int objs;

	sc.gfp_mask = -1;
	sc.nr_to_scan = 0;

	objs = heap->shrinker.count_objects(&heap->shrinker, &sc);
	*val = objs;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(debug_shrink_fops, debug_shrink_get,
			debug_shrink_set, "%llu\n");
#endif

=======
>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance
void ion_device_add_heap(struct ion_device *dev, struct ion_heap *heap)
{
	spin_lock_init(&heap->free_lock);
	heap->free_list_size = 0;

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_init_deferred_free(heap);

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE || heap->ops->shrink)
		ion_heap_init_shrinker(heap);

	heap->dev = dev;
<<<<<<< HEAD
	down_write(&dev->lock);
	/* use negative heap->id to reverse the priority -- when traversing
	   the list later attempt higher id numbers first */
	plist_node_init(&heap->node, -heap->id);
	plist_add(&heap->node, &dev->heaps);
	debug_file = debugfs_create_file(heap->name, 0664,
					dev->heaps_debug_root, heap,
					&debug_heap_fops);

	if (!debug_file) {
		char buf[256], *path;

		path = dentry_path(dev->heaps_debug_root, buf, 256);
		pr_err("Failed to create heap debugfs at %s/%s\n",
			path, heap->name);
	}

#ifdef DEBUG_HEAP_SHRINKER
	if (heap->shrinker.count_objects && heap->shrinker.scan_objects) {
		char debug_name[64];

		snprintf(debug_name, 64, "%s_shrink", heap->name);
		debug_file = debugfs_create_file(
			debug_name, 0644, dev->heaps_debug_root, heap,
			&debug_shrink_fops);
		if (!debug_file) {
			char buf[256], *path;

			path = dentry_path(dev->heaps_debug_root, buf, 256);
			pr_err("Failed to create heap shrinker debugfs at %s/%s\n",
				path, debug_name);
		}
	}
#endif
	up_write(&dev->lock);
}

int ion_walk_heaps(struct ion_client *client, int heap_id,
			unsigned int type, void *data,
			int (*f)(struct ion_heap *heap, void *data))
=======
	plist_node_init(&heap->node, -heap->id);

	down_write(&dev->heap_lock);
	plist_add(&heap->node, &dev->heaps);
	up_write(&dev->heap_lock);
}

int ion_walk_heaps(struct ion_client *client, int heap_id,
		   enum ion_heap_type type, void *data,
		   int (*f)(struct ion_heap *heap, void *data))
>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance
{
	struct ion_device *dev = client->dev;
	struct ion_heap *heap;
	int ret = 0;

	down_write(&dev->heap_lock);
	plist_for_each_entry(heap, &dev->heaps, node) {
		if (heap->type == type && ION_HEAP(heap->id) == heap_id) {
			ret = f(heap, data);
			break;
		}
	}
	up_write(&dev->heap_lock);

	return ret;
}

struct ion_device *ion_device_create(long (*custom_ioctl)
				     (struct ion_client *client,
				      unsigned int cmd, unsigned long arg))
{
	struct ion_device *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

<<<<<<< HEAD
	idev->dev.minor = MISC_DYNAMIC_MINOR;
	idev->dev.name = "ion";
	idev->dev.fops = &ion_fops;
	idev->dev.parent = NULL;
	ret = misc_register(&idev->dev);
	if (ret) {
		pr_err("ion: failed to register misc device.\n");
		return ERR_PTR(ret);
	}

	idev->debug_root = debugfs_create_dir("ion", NULL);
	if (!idev->debug_root) {
		pr_err("ion: failed to create debugfs root directory.\n");
		goto debugfs_done;
	}
	idev->heaps_debug_root = debugfs_create_dir("heaps", idev->debug_root);
	if (!idev->heaps_debug_root) {
		pr_err("ion: failed to create debugfs heaps directory.\n");
		goto debugfs_done;
	}
	idev->clients_debug_root = debugfs_create_dir("clients",
						idev->debug_root);
	if (!idev->clients_debug_root)
		pr_err("ion: failed to create debugfs clients directory.\n");

debugfs_done:

	idev->custom_ioctl = custom_ioctl;
	idev->buffers = RB_ROOT;
	mutex_init(&idev->buffer_lock);
	init_rwsem(&idev->lock);
	plist_head_init(&idev->heaps);
	idev->clients = RB_ROOT;
	ion_dev = idev;
	return idev;
}
=======
	ion_sg_table_pool = KMEM_CACHE(sg_table, SLAB_HWCACHE_ALIGN);
	if (!ion_sg_table_pool)
		goto free_dev;

	ion_page_pool = kmem_cache_create("ion_page", PAGE_SIZE, PAGE_SIZE,
					  SLAB_HWCACHE_ALIGN, NULL);
	if (!ion_page_pool)
		goto free_table_pool;
>>>>>>> efc798287015... ion: Overhaul for vastly improved clarity and performance

	dev->dev.minor = MISC_DYNAMIC_MINOR;
	dev->dev.name = "ion";
	dev->dev.fops = &ion_fops;
	dev->dev.parent = NULL;
	ret = misc_register(&dev->dev);
	if (ret)
		goto free_page_pool;

	dev->custom_ioctl = custom_ioctl;
	init_rwsem(&dev->heap_lock);
	plist_head_init(&dev->heaps);
	return dev;

free_page_pool:
	kmem_cache_destroy(ion_page_pool);
free_table_pool:
	kmem_cache_destroy(ion_sg_table_pool);
free_dev:
	kfree(dev);
	return ERR_PTR(-ENOMEM);
}

void __init ion_reserve(struct ion_platform_data *data)
{
	phys_addr_t paddr;
	int i;

	for (i = 0; i < data->nr; i++) {
		if (!data->heaps[i].size)
			continue;

		if (data->heaps[i].base) {
			memblock_reserve(data->heaps[i].base,
					 data->heaps[i].size);
		} else {
			paddr = memblock_alloc_base(data->heaps[i].size,
						    data->heaps[i].align,
						    MEMBLOCK_ALLOC_ANYWHERE);
			if (paddr)
				data->heaps[i].base = paddr;
		}
	}
}

struct ion_buffer *get_buffer(struct ion_handle *handle)
{
	struct ion_buffer *buffer = handle->buffer;

	return buffer;
}
