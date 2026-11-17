package ai.certkor.certone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Scan/ingest options, enums and digests. */
class OptionsTest {

  @Test
  void defaultsSendNothing() {
    ScanOptions options = ScanOptions.defaults();

    assertTrue(options.formFields(true).isEmpty());
    assertTrue(options.asset().isEmpty());
    assertTrue(options.packs().isEmpty());
    assertSame(options, ScanOptions.defaults());
    assertTrue(IngestOptions.defaults().bodyFields().isEmpty());
  }

  @Test
  void scanOptionsFieldsUseWireNamesAndValues() {
    ScanOptions options =
        ScanOptions.builder()
            .asset("  Fraud Scorer ")
            .environment(Environment.EDGE)
            .countryCode("EU")
            .failOn(FailOn.NONE)
            .packs(List.of("eu-ai-act-core", " iso-42001-core "))
            .snapshotRef("git:acme/fraud@abc")
            .commitHash("abc")
            .tee("amd_sev_snp")
            .build();

    assertEquals(
        Map.of(
            "asset", "Fraud Scorer",
            "environment", "edge",
            "country_code", "EU",
            "fail_on", "none",
            "packs", "eu-ai-act-core,iso-42001-core",
            "snapshot_ref", "git:acme/fraud@abc",
            "commit_hash", "abc",
            "tee", "amd_sev_snp"),
        options.formFields(true));
    assertFalse(options.formFields(false).containsKey("tee"));
    assertEquals(FailOn.NONE, options.failOn().orElseThrow());
  }

  @Test
  void scanOptionsAreImmutableValues() {
    List<String> packs = new ArrayList<>(List.of("eu-ai-act-core"));
    ScanOptions.Builder builder = ScanOptions.builder().asset("a").packs(packs);
    ScanOptions first = builder.build();
    packs.add("iso-42001-core");
    builder.asset("b");

    assertEquals(List.of("eu-ai-act-core"), first.packs());
    assertEquals("a", first.asset().orElseThrow());
    assertThrows(UnsupportedOperationException.class, () -> first.packs().add("x"));
    assertEquals(first, first.toBuilder().build());
    assertEquals(first.hashCode(), first.toBuilder().build().hashCode());
    assertNotEquals(first, first.toBuilder().asset(null).build());
    assertTrue(first.toBuilder().asset(null).build().asset().isEmpty());
    assertEquals("ScanOptions{asset=a, packs=eu-ai-act-core}", first.toString());
  }

  @Test
  void scanOptionsRejectInvalidValues() {
    assertThrows(IllegalArgumentException.class, () -> ScanOptions.builder().asset(" "));
    assertThrows(IllegalArgumentException.class, () -> ScanOptions.builder().countryCode(""));
    assertThrows(IllegalArgumentException.class, () -> ScanOptions.builder().packs("a,b"));
    assertThrows(IllegalArgumentException.class, () -> ScanOptions.builder().packs("ok", " "));
    assertThrows(NullPointerException.class, () -> ScanOptions.builder().packs("ok", null));
    assertTrue(ScanOptions.builder().packs((String[]) null).build().packs().isEmpty());
  }

  @Test
  void ingestOptionsFields() {
    IngestOptions options =
        IngestOptions.builder()
            .asset("Fraud Scorer")
            .environment(Environment.EDGE)
            .countryCode("EU")
            .snapshotRef("git:org/repo@sha")
            .inputDigest("sha256:00")
            .repo("org/repo")
            .commitHash("sha")
            .build();

    assertEquals(
        List.of(
            "asset", "environment", "country_code", "snapshot_ref", "input_digest", "repo",
            "commit_hash"),
        List.copyOf(options.bodyFields().keySet()));
    assertEquals("edge", options.bodyFields().get("environment"));
    assertEquals(options, options.toBuilder().build());
    assertEquals(options.hashCode(), options.toBuilder().build().hashCode());
    assertThrows(IllegalArgumentException.class, () -> IngestOptions.builder().repo(" "));
  }

  @Test
  void enumsMapToWireValues() {
    assertEquals("vscode", Environment.VSCODE.wireValue());
    assertEquals(Environment.JUPYTER, Environment.fromWireValue(" Jupyter "));
    assertEquals(7, Environment.values().length);
    assertThrows(IllegalArgumentException.class, () -> Environment.fromWireValue("mainframe"));
    assertThrows(IllegalArgumentException.class, () -> Environment.fromWireValue(null));
    assertEquals(FailOn.MEDIUM, FailOn.fromWireValue("MEDIUM"));
    assertEquals("low", FailOn.LOW.toString());
    assertThrows(IllegalArgumentException.class, () -> FailOn.fromWireValue("critical"));
  }

  @Test
  void sha256MatchesKnownVectors(@TempDir Path dir) throws IOException {
    String abc = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    byte[] bytes = "abc".getBytes(StandardCharsets.US_ASCII);
    Path file = dir.resolve("abc.bin");
    Files.write(file, bytes);

    assertEquals(abc, Digests.sha256(bytes));
    assertEquals(abc, Digests.sha256(file));
    assertEquals(abc, Digests.sha256(new ByteArrayInputStream(bytes)));
    assertEquals(
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        Digests.sha256(new byte[0]));
    assertThrows(UncheckedIOException.class, () -> Digests.sha256(dir.resolve("absent")));
  }

  @Test
  void sha256OfLargeFileIsStreamed(@TempDir Path dir) throws IOException {
    byte[] content = new byte[1_000_003];
    for (int i = 0; i < content.length; i++) {
      content[i] = (byte) (i ^ (i >>> 8));
    }
    Path file = dir.resolve("big.bin");
    Files.write(file, content);

    assertEquals(Digests.sha256(content), Digests.sha256(file));
  }
}
