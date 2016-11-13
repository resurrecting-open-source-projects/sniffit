/* Sniffit Config File include                                                          */

void clear_list_buffer (struct cfg_file_contense *);
struct cfg_file_contense *adjust_select_from_list (void);
struct cfg_file_contense *adjust_select_to_list (void);
struct cfg_file_contense *adjust_deselect_from_list (void);
struct cfg_file_contense *adjust_deselect_to_list (void);
char *clean_string (char *); 
char *clean_filename (char *);
void make_nr_dot (char *);
void interprete_line (char *);
void read_cfg_file (char *);    
