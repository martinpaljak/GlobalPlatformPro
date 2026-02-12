package pro.javacard.gp.data;

import java.util.Optional;

// Container of interfaces for defining EMV (and other) data structures
public final class Data {

    private Data() {}

    // The basic identifier for a data unit
    public interface DataUnit {}

    // native to Enum, defined for record. Ex: DGI8002
    public interface Named {
        String name();
    }

    // With a description. Ex: Accumulator 2 Remaining Value
    public interface Described extends Named {
        default String description() {
            return "(%s ?)".formatted(name());
        }
    }

    // Reference to documentation
    public interface Documented extends Described {
        default Optional<String> documentation() {
            return Optional.empty();
        }
    }
}
