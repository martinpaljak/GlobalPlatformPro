package pro.javacard.gp;

// ServiceLoader SPI for next-gen tool (JDK 21+)
public interface ToolExtension {
    int run(String[] args);
}
