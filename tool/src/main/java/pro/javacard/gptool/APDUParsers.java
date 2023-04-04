package pro.javacard.gptool;

import apdu4j.core.CommandAPDU;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import pro.javacard.gp.GPUtils;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

public class APDUParsers {
    static final ObjectMapper cbor;

    static final ObjectMapper json;

    static {
        // When using strings, have hex instead of b64
        SimpleModule hexModule = new SimpleModule();
        hexModule.addSerializer(byte[].class, new BytesAsHexSerializer());
        hexModule.addDeserializer(byte[].class, new BytesAsHexDeserializer());

        json = new ObjectMapper();
        json.registerModule(hexModule);
        json.enable(JsonReadFeature.ALLOW_UNQUOTED_FIELD_NAMES.mappedFeature());
        json.enable(JsonReadFeature.ALLOW_JAVA_COMMENTS.mappedFeature());
        json.enable(JsonReadFeature.ALLOW_YAML_COMMENTS.mappedFeature());
        json.enable(JsonReadFeature.ALLOW_SINGLE_QUOTES.mappedFeature());
        json.enable(JsonReadFeature.ALLOW_TRAILING_COMMA.mappedFeature());

        cbor = new CBORMapper();
    }


    static public class BytesAsHexDeserializer extends JsonDeserializer<byte[]> {
        @Override
        public byte[] deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
            return Hex.decode(jsonParser.getValueAsString());
        }
    }

    static public class BytesAsHexSerializer extends JsonSerializer<byte[]> {

        @Override
        public void serialize(byte[] bytes, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            jsonGenerator.writeString(Hex.toHexString(bytes));
        }
    }


    static String hex_cleanup(String s) {
        // Delete: " ", ":", "0x"
        return s.replaceAll("(\\s+|0x|0X|:)", "");
    }

    static byte[] validate(byte[] apdu) {
        return new CommandAPDU(apdu).getBytes();
    }


    public static String visualize_structure(byte[] b) {
        // Try CBOR
        try {
            JsonNode json = cbor.readTree(b);
            return json.toPrettyString();
        } catch (IOException e) {
            // Not CBOR. TLV ?
            try {
                List<String> tlv = GPUtils.visualize_tlv(b);
                return String.join("\n", tlv);
            } catch (IllegalArgumentException e2) {
                // Do nothing
            }
        }
        // HEX fallback
        return Hex.toHexString(b);
    }

    static byte[] stringToAPDU(String s) {
        Objects.requireNonNull(s);

        s = s.trim();

        if (s.length() == 0)
            throw new IllegalArgumentException("Empty APDU string");

        try {
            // If curly strings, parse as payload and dump into compact CBOR
            int curly = s.indexOf('{');
            if (curly > 0) {
                byte[] header = Hex.decode(hex_cleanup(s.substring(0, curly)));
                if (header.length == 4) {
                    JsonNode j = json.readTree(s.substring(curly));
                    byte[] c = cbor.writeValueAsBytes(j);
                    return validate(GPUtils.concatenate(header, new byte[]{(byte) (c.length & 0xFF)}, c));
                }
            } else {
                // If it works as valid APDU - great.
                try {
                    return validate(Hex.decode(hex_cleanup(s)));
                } catch (IllegalArgumentException | DecoderException e) {
                    // Otherwise support giving header and payload separated by space and fill payload length in automagically
                    String[] pieces = s.split("\\s+");
                    if (pieces.length == 2) {
                        byte[][] pcs = new byte[2][];
                        pcs[0] = Hex.decode(hex_cleanup(pieces[0]));
                        pcs[1] = Hex.decode(hex_cleanup(pieces[1]));
                        if (pcs[0].length == 4) {
                            return validate(GPUtils.concatenate(pcs[0], new byte[]{(byte) (pcs[1].length & 0xFF)}, pcs[1]));
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new IllegalArgumentException(String.format("Could not parse \"%s\": %s", s, e.getMessage()), e);
        }
        throw new IllegalArgumentException(String.format("Don't know how to handle\"%s\"", s));
    }
}
