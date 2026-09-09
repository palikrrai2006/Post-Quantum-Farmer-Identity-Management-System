package com.farmeridentity;

import com.machinezoo.sourceafis.FingerprintImage;
import com.machinezoo.sourceafis.FingerprintTemplate;
import com.machinezoo.sourceafis.FingerprintMatcher;
import org.json.JSONObject;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * SourceAfisBridge
 * =================
 * Command-line bridge so the Python side (biometric/sourceafis_bridge.py)
 * can invoke REAL SourceAFIS template extraction and matching via subprocess,
 * without needing a JVM-in-process binding.
 *
 * This is the actual SourceAFIS engine — not a re-implementation. All scores
 * and template bytes below come from real com.machinezoo.sourceafis calls.
 *
 * Usage:
 *   java -jar sourceafis-bridge.jar extract <image_path>
 *       -> prints JSON: {"template_base64": "...", "template_size_bytes": N, "extraction_time_ns": N}
 *
 *   java -jar sourceafis-bridge.jar match <template1_path> <template2_path>
 *       -> prints JSON: {"score": <double>, "match_time_ns": N}
 *          (template files are the raw serialized template bytes written by `extract`,
 *           or produced by decoding template_base64 from Python)
 */
public class SourceAfisBridge {

    public static void main(String[] args) throws Exception {
        PrintStream out = System.out;

        if (args.length == 0) {
            printUsageAndExit();
        }

        String command = args[0];

        if (command.equals("extract")) {
            if (args.length != 2) {
                System.err.println("Usage: extract <image_path>");
                System.exit(2);
            }
            extract(args[1], out);

        } else if (command.equals("match")) {
            if (args.length != 3) {
                System.err.println("Usage: match <template1_path> <template2_path>");
                System.exit(2);
            }
            match(args[1], args[2], out);

        } else {
            printUsageAndExit();
        }
    }

    private static void extract(String imagePath, PrintStream out) throws Exception {
        byte[] imageBytes = Files.readAllBytes(Paths.get(imagePath));

        long start = System.nanoTime();

        FingerprintImage image = new FingerprintImage()
                .dpi(500)
                .decode(imageBytes);
        FingerprintTemplate template = new FingerprintTemplate(image);
        byte[] serialized = template.toByteArray();

        long elapsedNs = System.nanoTime() - start;

        JSONObject result = new JSONObject();
        result.put("template_base64", Base64.getEncoder().encodeToString(serialized));
        result.put("template_size_bytes", serialized.length);
        result.put("extraction_time_ns", elapsedNs);

        out.println(result.toString());
    }

    private static void match(String template1Path, String template2Path, PrintStream out) throws Exception {
        byte[] t1Bytes = Files.readAllBytes(Paths.get(template1Path));
        byte[] t2Bytes = Files.readAllBytes(Paths.get(template2Path));

        long start = System.nanoTime();

        FingerprintTemplate probe = new FingerprintTemplate(t1Bytes);
        FingerprintTemplate candidate = new FingerprintTemplate(t2Bytes);

        FingerprintMatcher matcher = new FingerprintMatcher(probe);
        double score = matcher.match(candidate);

        long elapsedNs = System.nanoTime() - start;

        JSONObject result = new JSONObject();
        result.put("score", score);
        result.put("match_time_ns", elapsedNs);

        out.println(result.toString());
    }

    private static void printUsageAndExit() {
        System.err.println("Usage:");
        System.err.println("  java -jar sourceafis-bridge.jar extract <image_path>");
        System.err.println("  java -jar sourceafis-bridge.jar match <template1_path> <template2_path>");
        System.exit(2);
    }
}
