#ifndef CONFIG_H
#define CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

enum config { SERVER_HOST, SERVER_PORT, LOCAL_PORT, PASSWORD };
enum mode { SERVER, CLIENT };

void set_mode(enum mode m);
enum mode get_mode();

const char* get_config(enum config c);
void set_config(enum config c, const char* value);

#ifdef __cplusplus
}
#endif

#endif
