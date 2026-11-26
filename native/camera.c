/* UTCIEID camera preview worker. Uses the system libhybris camera C ABI.
 * No photos, files, microphone, network access or QR payloads in this process.
 * stdout is a bounded binary stream: magic,width,height,rotation,length (LE32), Y8.
 * Closing stdin stops capture. A separate process bounds HAL hangs/crashes.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <EGL/egl.h>
typedef unsigned int GLenum, GLuint;
typedef int GLint, GLsizei;
enum { GL_LINEAR = 0x2601, GL_CLAMP_TO_EDGE = 0x812F, GL_TEXTURE_MIN_FILTER = 0x2801,
       GL_TEXTURE_MAG_FILTER = 0x2800, GL_TEXTURE_WRAP_S = 0x2802, GL_TEXTURE_WRAP_T = 0x2803 };

typedef struct CameraControl Camera;
typedef struct {
    void (*error)(void *); void (*shutter)(void *); void (*focus)(void *);
    void (*zoom)(void *, int32_t);
    void (*raw)(void *, uint32_t, void *); void (*jpeg)(void *, uint32_t, void *);
    void (*texture)(void *); void *context;
    void (*preview)(void *, uint32_t, void *);
} Listener;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static uint8_t *latest;
static size_t plane_size;
static int ready, texture_ready, failed, chosen_w, chosen_h;
static volatile sig_atomic_t stopped;
static int focus_requested;
static int diagnostic_fd = -1;
static void stage(const char *name) {
    if (diagnostic_fd >= 0 && (write(diagnostic_fd, name, strlen(name)) < 0 || write(diagnostic_fd, "\n", 1) < 0)) {
        close(diagnostic_fd); diagnostic_fd = -1;
    }
}
static void stop_signal(int signal_number) { (void)signal_number; stopped = 1; }
static void camera_error(void *context) { (void)context; pthread_mutex_lock(&gate); failed = 1; pthread_mutex_unlock(&gate); }
static void texture_frame(void *context) { (void)context; pthread_mutex_lock(&gate); texture_ready = 1; pthread_mutex_unlock(&gate); }
static void frame(void *data, uint32_t size, void *context) {
    (void)context;
    pthread_mutex_lock(&gate);
    if (latest && data && size >= plane_size) { memcpy(latest, data, plane_size); ready = 1; }
    pthread_mutex_unlock(&gate);
}
static void preview_size(void *context, int w, int h) {
    (void)context;
    if (w >= 320 && h >= 240 && w <= 1280 && h <= 960 && w * h > chosen_w * chosen_h) { chosen_w = w; chosen_h = h; }
}
static int read_control(void) {
    char commands[32];
    ssize_t n = read(STDIN_FILENO, commands, sizeof(commands));
    if (n < 0 && errno == EINTR) return 1;
    if (n <= 0) return 0;
    for (ssize_t i = 0; i < n; ++i) if (commands[i] == 'f') focus_requested = 1;
    return 1;
}
static int64_t milliseconds(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int send_all(int fd, const void *data, size_t length) {
    const uint8_t *p = data;
    while (length && !stopped) {
        struct pollfd descriptors[] = { { fd, POLLOUT, 0 }, { STDIN_FILENO, POLLIN, 0 } };
        int result = poll(descriptors, 2, 500);
        if (result < 0 && errno == EINTR) continue;
        if (result == 0) continue;
        if (result < 0) return 0;
        if (descriptors[1].revents && !read_control()) return 0;
        if (!(descriptors[0].revents & POLLOUT)) {
            if (descriptors[0].revents) return 0;
            continue;
        }
        ssize_t count = write(fd, p, length);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return 0;
        p += count; length -= (size_t)count;
    }
    return length == 0;
}
#define API_FROM(lib, type, name, args) type (*name) args = (type (*) args)dlsym(lib, #name); if (!name) return 10
#define API(type, name, args) API_FROM(library, type, name, args)
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--diagnose") == 0) diagnostic_fd = dup(STDERR_FILENO);
    signal(SIGTERM, stop_signal); signal(SIGINT, stop_signal); signal(SIGPIPE, SIG_IGN);
    int output = dup(STDOUT_FILENO), sink = open("/dev/null", O_WRONLY);
    if (output < 0 || sink < 0) return 10;
    /* HAL messages must never corrupt the frame stream or become application logs. */
    dup2(sink, STDOUT_FILENO); dup2(sink, STDERR_FILENO); close(sink);
    fcntl(output, F_SETFL, fcntl(output, F_GETFL) | O_NONBLOCK);
    void *library = dlopen("libcamera.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library) return 10;
    stage("camera: library loaded");
    API(int, android_camera_get_number_of_devices, (void));
    API(int, android_camera_get_device_info, (int32_t, int *, int *));
    API(Camera *, android_camera_connect_by_id, (int32_t, Listener *));
    API(void, android_camera_disconnect, (Camera *));
    API(void, android_camera_enumerate_supported_preview_sizes, (Camera *, void (*)(void *, int, int), void *));
    API(void, android_camera_set_preview_size, (Camera *, int, int));
    API(void, android_camera_get_preview_size, (Camera *, int *, int *));
    API(void, android_camera_set_preview_format, (Camera *, int));
    API(void, android_camera_set_auto_focus_mode, (Camera *, int));
    API(void, android_camera_start_autofocus, (Camera *));
    API(void, android_camera_stop_autofocus, (Camera *));
    API(int, android_camera_set_preview_callback_mode, (Camera *, int));
    API(void, android_camera_start_preview, (Camera *));
    API(void, android_camera_stop_preview, (Camera *));
    API(void, android_camera_set_preview_texture, (Camera *, int));
    API(void, android_camera_update_preview_texture, (Camera *));
    /* Ubuntu Touch's camera permission agent identifies a requesting PID through
     * its Mir session. A worker with only an offscreen EGL context has no session
     * and the permission request would wait forever. No visible window is needed. */
    void *mir_library = dlopen("libmirclient.so.9", RTLD_NOW | RTLD_LOCAL);
    if (!mir_library) return 17;
    API_FROM(mir_library, void *, mir_connect_sync, (const char *, const char *));
    API_FROM(mir_library, bool, mir_connection_is_valid, (const void *));
    API_FROM(mir_library, void, mir_connection_release, (void *));
    char mir_socket[128];
    snprintf(mir_socket, sizeof(mir_socket), "/run/user/%u/mir_socket", (unsigned)getuid());
    const char *app_id = getenv("APP_ID");
    stage("camera: connecting permission session");
    void *mir = mir_connect_sync(mir_socket, app_id ? app_id : "utcieid.milattanzio_utcieid");
    if (!mir || !mir_connection_is_valid(mir)) return 17;
    stage("camera: permission session ready");
    /* Use the Android EGL implementation, independently of Avalonia's renderer. */
    setenv("HYBRIS_EGLPLATFORM", "null", 1);
    setenv("__EGL_VENDOR_LIBRARY_FILENAMES", "/usr/share/glvnd/egl_vendor.d/10_libhybris.json", 1);
    void *egl_library = dlopen("libEGL.so.1", RTLD_NOW | RTLD_LOCAL);
    void *gl_library = dlopen("libGLESv2_libhybris.so.2", RTLD_NOW | RTLD_LOCAL);
    if (!egl_library || !gl_library) return 16;
    API_FROM(egl_library, EGLDisplay, eglGetDisplay, (EGLNativeDisplayType));
    API_FROM(egl_library, EGLBoolean, eglInitialize, (EGLDisplay, EGLint *, EGLint *));
    API_FROM(egl_library, EGLBoolean, eglChooseConfig, (EGLDisplay, const EGLint *, EGLConfig *, EGLint, EGLint *));
    API_FROM(egl_library, EGLContext, eglCreateContext, (EGLDisplay, EGLConfig, EGLContext, const EGLint *));
    API_FROM(egl_library, EGLSurface, eglCreatePbufferSurface, (EGLDisplay, EGLConfig, const EGLint *));
    API_FROM(egl_library, EGLBoolean, eglMakeCurrent, (EGLDisplay, EGLSurface, EGLSurface, EGLContext));
    API_FROM(egl_library, EGLBoolean, eglDestroySurface, (EGLDisplay, EGLSurface));
    API_FROM(egl_library, EGLBoolean, eglDestroyContext, (EGLDisplay, EGLContext));
    API_FROM(egl_library, EGLBoolean, eglTerminate, (EGLDisplay));
    API_FROM(gl_library, void, glGenTextures, (GLsizei, GLuint *));
    API_FROM(gl_library, void, glBindTexture, (GLenum, GLuint));
    API_FROM(gl_library, void, glTexParameteri, (GLenum, GLenum, GLint));
    API_FROM(gl_library, void, glDeleteTextures, (GLsizei, const GLuint *));
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    stage("camera: EGL display selected");
    if (display == EGL_NO_DISPLAY || !eglInitialize(display, NULL, NULL)) return 16;
    EGLint configs = 0;
    EGLConfig config;
    const EGLint attributes[] = { EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_NONE };
    const EGLint context_attributes[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    const EGLint surface_attributes[] = { EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE };
    if (!eglChooseConfig(display, attributes, &config, 1, &configs) || configs != 1) return 16;
    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attributes);
    EGLSurface surface = eglCreatePbufferSurface(display, config, surface_attributes);
    if (context == EGL_NO_CONTEXT || surface == EGL_NO_SURFACE || !eglMakeCurrent(display, surface, surface, context)) return 16;
    stage("camera: EGL context ready");
    GLuint texture = 0;
    glGenTextures(1, &texture); glBindTexture(0x8D65 /* GL_TEXTURE_EXTERNAL_OES */, texture);
    glTexParameteri(0x8D65, GL_TEXTURE_MIN_FILTER, GL_LINEAR); glTexParameteri(0x8D65, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(0x8D65, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE); glTexParameteri(0x8D65, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    int count = android_camera_get_number_of_devices(), selected = -1, rotation = 0;
    stage("camera: devices enumerated");
    if (count < 1 || count > 32) return 11;
    for (int i = 0; i < count; ++i) {
        int facing = -1, angle = 0;
        if (android_camera_get_device_info(i, &facing, &angle) == 0 && facing == 0) { selected = i; rotation = angle; break; }
    }
    if (selected < 0 || rotation < 0 || rotation > 270 || rotation % 90) return 11;
    Listener listener = { .error = camera_error, .texture = texture_frame, .preview = frame };
    stage("camera: connecting");
    Camera *camera = android_camera_connect_by_id(selected, &listener);
    if (!camera) return 12;
    stage("camera: connected");
    int result = 0, w = 0, h = 0;
    android_camera_enumerate_supported_preview_sizes(camera, preview_size, NULL);
    if (!chosen_w) { result = 13; goto finish; }
    android_camera_set_preview_size(camera, chosen_w, chosen_h);
    android_camera_set_preview_format(camera, 1); /* YUV420SP/NV21: first plane is Y8. */
    android_camera_get_preview_size(camera, &w, &h);
    if (w < 1 || h < 1 || w > 1280 || h > 960) { result = 13; goto finish; }
    plane_size = (size_t)w * h;
    latest = malloc(plane_size);
    uint8_t *copy = malloc(plane_size);
    if (!latest || !copy) { free(copy); result = 13; goto finish; }
    android_camera_set_auto_focus_mode(camera, 4); /* continuous picture: close, still QR */
    if (android_camera_set_preview_callback_mode(camera, 1) != 0) { free(copy); result = 13; goto finish; }
    android_camera_set_preview_texture(camera, (int)texture);
    android_camera_start_preview(camera);
    stage("camera: preview started");
    int idle = 0;
    int64_t initial_focus = milliseconds() + 500, focus_until = 0;
    while (!stopped) {
        struct pollfd input = { STDIN_FILENO, POLLIN, 0 };
        int polled = poll(&input, 1, 100);
        if (polled > 0 && input.revents && !read_control()) break;
        int64_t now = milliseconds();
        if (focus_requested || (initial_focus && now >= initial_focus)) {
            focus_requested = 0; initial_focus = 0;
            android_camera_stop_autofocus(camera);
            android_camera_start_autofocus(camera);
            focus_until = now + 3000;
        } else if (focus_until && now >= focus_until) {
            /* Release the explicit AF lock so continuous focusing follows distance. */
            android_camera_stop_autofocus(camera);
            focus_until = 0;
        }
        int have_frame, error, update_texture;
        pthread_mutex_lock(&gate);
        have_frame = ready; error = failed;
        update_texture = texture_ready; texture_ready = 0;
        if (have_frame) { memcpy(copy, latest, plane_size); ready = 0; }
        pthread_mutex_unlock(&gate);
        if (update_texture) android_camera_update_preview_texture(camera);
        if (error) { result = 14; break; }
        if (!have_frame) { if (++idle >= 150) { result = 15; break; } continue; }
        idle = 0;
        uint32_t header[] = { 0x314D4143, (uint32_t)w, (uint32_t)h, (uint32_t)rotation, (uint32_t)plane_size };
        if (!send_all(output, header, sizeof(header)) || !send_all(output, copy, plane_size)) break;
    }
    free(copy);
    android_camera_stop_autofocus(camera);
    android_camera_set_preview_callback_mode(camera, 0);
    android_camera_stop_preview(camera);
    android_camera_set_preview_texture(camera, 0);
finish:
    android_camera_disconnect(camera);
    pthread_mutex_lock(&gate); free(latest); latest = NULL; pthread_mutex_unlock(&gate);
    close(output);
    glDeleteTextures(1, &texture);
    eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroySurface(display, surface); eglDestroyContext(display, context); eglTerminate(display);
    mir_connection_release(mir);
    /* Process exit also releases any vendor state; do not dlclose callback code. */
    return result;
}
