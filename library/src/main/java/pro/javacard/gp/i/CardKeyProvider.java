package pro.javacard.gp.i;

import pro.javacard.gp.GPCardKeys;

import java.util.Optional;

public interface CardKeyProvider {
    Optional<GPCardKeys> getCardKeys(String spec);
}
