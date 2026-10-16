package com.aricummings.enclave;

import android.media.AudioFormat;
import android.media.Image;
import android.media.MediaCodec;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** The person's own video file, read with the system's decoders
 *  (MediaExtractor, MediaCodec) for Enclave to encode again
 *  (enclave-platform's video/mediacodec.rs drives it). Frames come out as
 *  I420; sound as 16-bit PCM at the file's rate and channels. */
final class VideoReader {
    private static final long WAIT_US = 10_000;
    private final MediaExtractor videoIn = new MediaExtractor();
    private final MediaExtractor audioIn = new MediaExtractor();
    private MediaCodec video;
    private MediaCodec audio;
    private final MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
    private int width, height, rotation;
    private long durationUs;
    private int rate = 48000, channels = 1;
    private boolean videoFed, videoDone, audioFed, audioDone;
    private byte[] frame = new byte[0];
    private long frameUs;
    private final java.io.ByteArrayOutputStream sound = new java.io.ByteArrayOutputStream();

    static VideoReader open(String path) throws IOException {
        VideoReader r = new VideoReader();
        try {
            r.start(path);
            return r;
        } catch (IOException | RuntimeException e) {
            r.close();
            throw e;
        }
    }

    private void start(String path) throws IOException {
        videoIn.setDataSource(path);
        MediaFormat vf = select(videoIn, "video/");
        if (vf == null) throw new IOException("no picture");
        width = vf.getInteger(MediaFormat.KEY_WIDTH);
        height = vf.getInteger(MediaFormat.KEY_HEIGHT);
        rotation = vf.containsKey(MediaFormat.KEY_ROTATION) ? vf.getInteger(MediaFormat.KEY_ROTATION) : 0;
        durationUs = vf.containsKey(MediaFormat.KEY_DURATION) ? vf.getLong(MediaFormat.KEY_DURATION) : 0;
        vf.setInteger(MediaFormat.KEY_COLOR_FORMAT, android.media.MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible);
        video = MediaCodec.createDecoderByType(vf.getString(MediaFormat.KEY_MIME));
        video.configure(vf, null, null, 0);
        video.start();
        audioIn.setDataSource(path);
        MediaFormat af = select(audioIn, "audio/");
        if (af == null) {
            audioDone = true;
            return;
        }
        rate = af.getInteger(MediaFormat.KEY_SAMPLE_RATE);
        channels = af.getInteger(MediaFormat.KEY_CHANNEL_COUNT);
        af.setInteger(MediaFormat.KEY_PCM_ENCODING, AudioFormat.ENCODING_PCM_16BIT);
        audio = MediaCodec.createDecoderByType(af.getString(MediaFormat.KEY_MIME));
        audio.configure(af, null, null, 0);
        audio.start();
    }

    private static MediaFormat select(MediaExtractor ex, String kind) {
        for (int i = 0; i < ex.getTrackCount(); i++) {
            MediaFormat f = ex.getTrackFormat(i);
            String mime = f.getString(MediaFormat.KEY_MIME);
            if (mime != null && mime.startsWith(kind)) {
                ex.selectTrack(i);
                return f;
            }
        }
        return null;
    }

    int width() { return width; }
    int height() { return height; }
    int rotation() { return rotation; }
    long durationMs() { return durationUs / 1000; }
    int soundRate() { return rate; }
    int soundChannels() { return channels; }
    byte[] frame() { return frame; }
    long frameUs() { return frameUs; }

    /** Decode up to the next frame; false at the end. */
    boolean next() {
        while (!videoDone) {
            if (!videoFed) videoFed = feed(video, videoIn);
            int out = video.dequeueOutputBuffer(info, WAIT_US);
            if (out < 0) continue;
            boolean end = (info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0;
            boolean got = false;
            if (info.size > 0) {
                Image img = video.getOutputImage(out);
                if (img != null) {
                    frame = i420(img);
                    frameUs = info.presentationTimeUs;
                    img.close();
                    got = true;
                }
            }
            video.releaseOutputBuffer(out, false);
            if (end) videoDone = true;
            if (got) return true;
        }
        return false;
    }

    /** The sound decoded up to the last frame (at the end, all of it). */
    short[] sound() {
        while (!audioDone) {
            if (!audioFed) audioFed = feed(audio, audioIn);
            int out = audio.dequeueOutputBuffer(info, WAIT_US);
            if (out == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                MediaFormat f = audio.getOutputFormat();
                rate = f.getInteger(MediaFormat.KEY_SAMPLE_RATE);
                channels = f.getInteger(MediaFormat.KEY_CHANNEL_COUNT);
                continue;
            }
            if (out < 0) {
                if (audioFed) continue;
                break;
            }
            long at = info.presentationTimeUs;
            if (info.size > 0) {
                ByteBuffer b = audio.getOutputBuffer(out);
                if (b != null) {
                    byte[] bytes = new byte[info.size];
                    b.position(info.offset);
                    b.get(bytes);
                    sound.write(bytes, 0, bytes.length);
                }
            }
            if ((info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) audioDone = true;
            audio.releaseOutputBuffer(out, false);
            if (!videoDone && at >= frameUs) break;
        }
        byte[] bytes = sound.toByteArray();
        sound.reset();
        short[] pcm = new short[bytes.length / 2];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(pcm);
        return pcm;
    }

    /** Give the decoder the next piece of the file; true once the file ends. */
    private static boolean feed(MediaCodec codec, MediaExtractor ex) {
        int in = codec.dequeueInputBuffer(WAIT_US);
        if (in < 0) return false;
        ByteBuffer buf = codec.getInputBuffer(in);
        int n = buf == null ? -1 : ex.readSampleData(buf, 0);
        if (n < 0) {
            codec.queueInputBuffer(in, 0, 0, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM);
            return true;
        }
        codec.queueInputBuffer(in, 0, n, ex.getSampleTime(), 0);
        ex.advance();
        return false;
    }

    /** The image's visible part as I420 (Y, then U, then V). */
    private byte[] i420(Image img) {
        android.graphics.Rect crop = img.getCropRect();
        int w = crop.width() & ~1, h = crop.height() & ~1;
        width = w;
        height = h;
        byte[] out = new byte[w * h * 3 / 2];
        int at = 0;
        Image.Plane[] planes = img.getPlanes();
        for (int p = 0; p < 3; p++) {
            ByteBuffer b = planes[p].getBuffer();
            int row = planes[p].getRowStride(), px = planes[p].getPixelStride();
            int pw = p == 0 ? w : w / 2, ph = p == 0 ? h : h / 2;
            int x0 = p == 0 ? crop.left : crop.left / 2, y0 = p == 0 ? crop.top : crop.top / 2;
            for (int y = 0; y < ph; y++) {
                int base = (y0 + y) * row + x0 * px;
                for (int x = 0; x < pw; x++) out[at++] = b.get(base + x * px);
            }
        }
        return out;
    }

    void close() {
        for (MediaCodec c : new MediaCodec[] {video, audio}) {
            if (c == null) continue;
            try { c.stop(); } catch (RuntimeException ignored) { }
            c.release();
        }
        videoIn.release();
        audioIn.release();
    }
}
