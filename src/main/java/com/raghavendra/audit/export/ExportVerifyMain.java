package com.raghavendra.audit.export;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Standalone command-line verifier for an export bundle.
 *
 * <pre>
 *   java -cp app.jar com.raghavendra.audit.export.ExportVerifyMain &lt;bundle.json&gt; [trustedPublicKey.b64]
 * </pre>
 *
 * Exit code 0 = valid, 1 = invalid/error. If a trusted public key file is given, the bundle's
 * embedded key is ignored and the signature is checked against the trusted key instead.
 */
public final class ExportVerifyMain {

    private ExportVerifyMain() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: ExportVerifyMain <bundle.json> [trustedPublicKey.b64]");
            System.exit(2);
            return;
        }
        ObjectMapper mapper = JsonMapper.builder().build();
        ExportBundle bundle = mapper.readValue(Files.readString(Path.of(args[0])), ExportBundle.class);

        ExportBundleVerifier verifier = new ExportBundleVerifier();
        ExportBundleVerifier.Result result;
        if (args.length >= 2) {
            String trustedKey = Files.readString(Path.of(args[1])).trim();
            result = verifier.verify(bundle, trustedKey);
        } else {
            result = verifier.verify(bundle);
        }

        System.out.println(result.valid() ? "VALID: " + result.detail() : "INVALID: " + result.detail());
        System.exit(result.valid() ? 0 : 1);
    }
}
