package pro.javacard.gp.emv;

import pro.javacard.gp.data.ByteRangeLocation;
import pro.javacard.gp.data.Data;

import java.util.LinkedHashMap;
import java.util.List;

public record DGI(int tag, String description, List<DGIElement> elements) implements Data.Described {

    public DGI {
        if (tag < 0) {
            throw new IllegalArgumentException("tag < 0");
        }
        elements = List.copyOf(elements);
    }

    public static DGI of(int tag, String description, DGIElement... elements) {
        return new DGI(tag, description, List.of(elements));
    }

    public static DGIElement with(Data.DataUnit element, ByteRangeLocation location) {
        return new DGIElement(element, location);
    }

    public static LinkedHashMap<Data.DataUnit, byte[]> parse(DGI dgi, byte[] blob) {
        LinkedHashMap<Data.DataUnit, byte[]> result = new LinkedHashMap<>();
        for (var e : dgi.elements()) {
            result.put(e.element(), ByteRangeLocation.extract(blob, e.location()));
        }
        return result;
    }

    @Override
    public String name() {
        return "DGI%04X".formatted(tag);
    }

    public record DGIElement(Data.DataUnit element, ByteRangeLocation location) {

    }
}
