#ifndef WTF_ARCHIVE_ROUTINES_H
#define WTF_ARCHIVE_ROUTINES_H
/* NOTE: THIS IS REPLACED BY ARCHIVE_ROUTINES2.H SINCE libarchive-devel IS NOT AVAILABLE ON THE MACHINE */
#include <stdio.h>
#include <stdlib.h>
#include <archive.h>
#include <archive_entry.h>

int
copy_data(struct archive *ar, struct archive *aw)
{
  int r;
  const void *buff;
  size_t size;
  la_int64_t offset;

  for (;;) {
    r = archive_read_data_block(ar, &buff, &size, &offset);
    if (r == ARCHIVE_EOF)
      return (ARCHIVE_OK);
    if (r < ARCHIVE_OK)
      return (r);
    r = archive_write_data_block(aw, buff, size, offset);
    if (r < ARCHIVE_OK) {
      fprintf(stderr, "%s\n", archive_error_string(aw));
      return (r);
    }
  }
}

size_t archive_to_file(char *outfile, int no_of_files, char **filename) {
  struct archive *a;
  struct archive_entry *entry;
  struct stat st;
  char buff[8192];
  int len;
  int fd;
  size_t written_size;
  int w=0;

  int rc ;
  a = archive_write_new();
  rc = archive_write_add_filter_gzip(a);
  rc = archive_write_set_format_pax_restricted(a);
  rc = archive_write_open_filename(a,outfile);
  for(int i=0;i < no_of_files;i++){
	  //	  printf("archiving file=%s\n",*filename);
	  stat(filename[i], &st);
	  entry = archive_entry_new();
	  archive_entry_set_pathname(entry, filename[i]);
	  archive_entry_set_size(entry, st.st_size);
	  archive_entry_set_filetype(entry, AE_IFREG);
	  archive_entry_set_perm(entry, 0644);
	  rc = archive_write_header(a, entry);
	  fd = open(filename[i], O_RDONLY);
	  len = read(fd, buff, sizeof(buff));
	  while ( len > 0 ) {
		  rc = archive_write_data(a, buff, len);
		  w+=rc;
		  len = read(fd, buff, sizeof(buff));
	  }
	  close(fd);
	  archive_entry_free(entry);
  }
  archive_write_close(a);
  archive_write_free(a);
  return w;
}

size_t archive_to_buffer(int no_of_files, char **filename,char *buffer,size_t buf_size) {
  struct archive *a;
  struct archive_entry *entry;
  struct stat st;
  char buff[8192];
  int len;
  int fd;
  size_t written_size = 0;
  int rc ;
  a = archive_write_new();
  rc = archive_write_add_filter_gzip(a);
  rc = archive_write_set_format_pax_restricted(a);
  rc = archive_write_open_memory(a,buffer,buf_size,&written_size);
  for(int i=0;i < no_of_files;i++){
	  printf("archiving file=%s\n",filename[i]);
	  stat(filename[i], &st);
	  entry = archive_entry_new();
	  archive_entry_set_pathname(entry, filename[i]);
	  archive_entry_set_size(entry, st.st_size);
	  archive_entry_set_filetype(entry, AE_IFREG);
	  archive_entry_set_perm(entry, 0644);
	  rc = archive_write_header(a, entry);
	  fd = open(filename[i], O_RDONLY);
	  len = read(fd, buff, sizeof(buff));
	  while ( len > 0 ) {
		  rc = archive_write_data(a, buff, len);
		  len = read(fd, buff, sizeof(buff));
	  }
	  close(fd);
	  archive_entry_free(entry);
  }
  archive_write_close(a);
  archive_write_free(a);
  return written_size;
}

int extract_from_buffer(const char *buffer,size_t buf_size)
{
  struct archive *a;
  struct archive *ext;
  struct archive_entry *entry;
  int flags;
  int r;

  /* Select which attributes we want to restore. */
  flags = ARCHIVE_EXTRACT_TIME;
  flags |= ARCHIVE_EXTRACT_PERM;
  flags |= ARCHIVE_EXTRACT_ACL;
  flags |= ARCHIVE_EXTRACT_FFLAGS;

  a = archive_read_new();
  archive_read_support_filter_gzip(a);
  archive_read_support_format_tar(a);
  ext = archive_write_disk_new();
  archive_write_disk_set_options(ext, flags);
  archive_write_disk_set_standard_lookup(ext);
  if ((r = archive_read_open_memory(a, buffer, buf_size))) {
	  archive_read_free(a);
	  archive_write_free(ext);
	  return -1;
  }
  for (;;) {
    r = archive_read_next_header(a, &entry);
    if (r == ARCHIVE_EOF)
      break;
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(a));
    if (r < ARCHIVE_WARN)
	    break;
    r = archive_write_header(ext, entry);
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(ext));
    else if (archive_entry_size(entry) > 0) {
      r = copy_data(a, ext);
      if (r < ARCHIVE_OK)
        fprintf(stderr, "%s\n", archive_error_string(ext));
      if (r < ARCHIVE_WARN)
	      break;
    }
    r = archive_write_finish_entry(ext);
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(ext));
    if (r < ARCHIVE_WARN)
	    break;
  }
  archive_read_close(a);
  archive_read_free(a);
  archive_write_close(ext);
  archive_write_free(ext);
  if(r < ARCHIVE_OK)
	  return -1;
   return 0;
}

int extract_file(const char *filename)
{
  struct archive *a;
  struct archive *ext;
  struct archive_entry *entry;
  int flags;
  int r;

  /* Select which attributes we want to restore. */
  flags = ARCHIVE_EXTRACT_TIME;
  flags |= ARCHIVE_EXTRACT_PERM;
  flags |= ARCHIVE_EXTRACT_ACL;
  flags |= ARCHIVE_EXTRACT_FFLAGS;

  a = archive_read_new();
  archive_read_support_filter_gzip(a);
  archive_read_support_format_tar(a);
  ext = archive_write_disk_new();
  archive_write_disk_set_options(ext, flags);
  archive_write_disk_set_standard_lookup(ext);
  if ((r = archive_read_open_filename(a, filename, 10240))) {
	  archive_read_free(a);
	  archive_write_free(ext);
	  return -1;
  }
  for (;;) {
    r = archive_read_next_header(a, &entry);
    if (r == ARCHIVE_EOF)
      break;
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(a));
    if (r < ARCHIVE_WARN)
	    break;
    r = archive_write_header(ext, entry);
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(ext));
    else if (archive_entry_size(entry) > 0) {
      r = copy_data(a, ext);
      if (r < ARCHIVE_OK)
        fprintf(stderr, "%s\n", archive_error_string(ext));
      if (r < ARCHIVE_WARN)
	      break;
    }
    r = archive_write_finish_entry(ext);
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(ext));
    if (r < ARCHIVE_WARN)
	    break;
  }
  archive_read_close(a);
  archive_read_free(a);
  archive_write_close(ext);
  archive_write_free(ext);
  if(r < ARCHIVE_OK)
	  return -1;
   return 0;
}

#endif // WTF_ARCHIVE_ROUTINES_H
