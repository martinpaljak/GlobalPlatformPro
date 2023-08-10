package pro.javacard.gp;

import java.util.Optional;

// The interface is here not in gptool, to be able to depend on library for plugins
public interface CardKeysProvider {
    Optional<GPCardKeys> getCardKeys(String spec);
}
