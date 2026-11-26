#include "openjpeg/openjpeg.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const uint8_t *data; size_t size, position; } source;
static OPJ_SIZE_T read_memory(void *dst, OPJ_SIZE_T count, void *context) {
    source *s = context;
    if (s->position == s->size) return (OPJ_SIZE_T)-1;
    if (count > s->size - s->position) count = s->size - s->position;
    memcpy(dst, s->data + s->position, count); s->position += count; return count;
}
static OPJ_OFF_T skip_memory(OPJ_OFF_T count, void *context) {
    source *s = context;
    if (count < 0 || (uint64_t)count > s->size - s->position) return -1;
    s->position += (size_t)count; return count;
}
static OPJ_BOOL seek_memory(OPJ_OFF_T position, void *context) {
    source *s = context;
    if (position < 0 || (uint64_t)position > s->size) return OPJ_FALSE;
    s->position = (size_t)position; return OPJ_TRUE;
}
static void quiet(const char *message, void *context) { (void)message; (void)context; }
static uint8_t clamp(int value) { return value < 0 ? 0 : value > 255 ? 255 : (uint8_t)value; }
static int sample(opj_image_comp_t *c, unsigned x, unsigned y, unsigned w, unsigned h) {
    int v = c->data[(size_t)(y * c->h / h) * c->w + x * c->w / w];
    if (c->sgnd) v += 1 << (c->prec - 1);
    return clamp((int)((int64_t)v * 255 / ((1 << c->prec) - 1)));
}
/* No paths, files, logs or global state: decode only a bounded in-memory portrait. */
int utcieid_decode_portrait(const uint8_t *data, size_t length, uint8_t **rgba, int *width, int *height) {
    int result = 0;
    opj_codec_t *codec = NULL; opj_stream_t *stream = NULL; opj_image_t *image = NULL;
    *rgba = NULL; *width = 0; *height = 0;
    if (!data || length < 12 || length > 1048576) return 0;
    codec = opj_create_decompress(data[0] == 0xff && data[1] == 0x4f ? OPJ_CODEC_J2K : OPJ_CODEC_JP2);
    if (!codec) goto done;
    opj_set_error_handler(codec, quiet, NULL); opj_set_warning_handler(codec, quiet, NULL); opj_set_info_handler(codec, quiet, NULL);
    opj_dparameters_t parameters; opj_set_default_decoder_parameters(&parameters);
    if (!opj_setup_decoder(codec, &parameters)) goto done;
    stream = opj_stream_default_create(OPJ_TRUE); if (!stream) goto done;
    source input = { data, length, 0 };
    opj_stream_set_user_data(stream, &input, NULL); opj_stream_set_user_data_length(stream, length);
    opj_stream_set_read_function(stream, read_memory); opj_stream_set_skip_function(stream, skip_memory); opj_stream_set_seek_function(stream, seek_memory);
    if (!opj_read_header(stream, codec, &image) || !image) goto done;
    unsigned w = image->x1 - image->x0, h = image->y1 - image->y0;
    if (!w || !h || w > 2048 || h > 2048 || (image->numcomps != 1 && image->numcomps != 3)) goto done;
    if (image->color_space == OPJ_CLRSPC_CMYK || image->color_space == OPJ_CLRSPC_EYCC) goto done;
    for (unsigned i = 0; i < image->numcomps; i++) {
        opj_image_comp_t *c = &image->comps[i];
        if (!c->w || !c->h || c->w > 2048 || c->h > 2048 || !c->prec || c->prec > 16) goto done;
    }
    if (!opj_decode(codec, stream, image) || !opj_end_decompress(codec, stream)) goto done;
    for (unsigned i = 0; i < image->numcomps; i++) if (!image->comps[i].data) goto done;
    *rgba = malloc((size_t)w * h * 4); if (!*rgba) goto done;
    for (unsigned y = 0; y < h; y++) for (unsigned x = 0; x < w; x++) {
        int r = sample(&image->comps[0], x, y, w, h), g = r, b = r;
        if (image->numcomps == 3) {
            g = sample(&image->comps[1], x, y, w, h); b = sample(&image->comps[2], x, y, w, h);
            if (image->color_space == OPJ_CLRSPC_SYCC) {
                int cb = g - 128, cr = b - 128, luma = r;
                r = luma + (91881 * cr >> 16); g = luma - ((22554 * cb + 46802 * cr) >> 16); b = luma + (116130 * cb >> 16);
            }
        }
        size_t offset = ((size_t)y * w + x) * 4;
        (*rgba)[offset] = clamp(r); (*rgba)[offset+1] = clamp(g); (*rgba)[offset+2] = clamp(b); (*rgba)[offset+3] = 255;
    }
    *width = (int)w; *height = (int)h; result = 1;
done:
    if (image) opj_image_destroy(image);
    if (stream) opj_stream_destroy(stream);
    if (codec) opj_destroy_codec(codec);
    return result;
}
void utcieid_free_portrait(void *pixels) { free(pixels); }
