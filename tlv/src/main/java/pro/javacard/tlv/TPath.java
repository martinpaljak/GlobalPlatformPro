// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT

package pro.javacard.tlv;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.stream.IntStream;
import java.util.stream.Stream;

// A path that addresses at most one node in a TLV tree and the operations that read or edit it.
public final class TPath {
    private final List<Segment> segments;

    private TPath(final List<Segment> segments) {
        this.segments = List.copyOf(segments);
    }

    // Always-true predicate for tag-only segments
    static final Predicate<byte[]> ANY = v -> true;

    // One step of a path: a tag and a value predicate, matched against a direct child
    public record Segment(Tag tag, Predicate<byte[]> value) {
        public Segment(final Tag tag) {
            this(tag, ANY);
        }

        public boolean matches(final TLV node) {
            return node.tag().equals(tag) && value.test(node.value());
        }
    }

    // --- construction ---
    public static TPath of(final Tag... tags) {
        return new TPath(Stream.of(tags).map(Segment::new).toList());
    }

    public static TPath of(final int... tags) {
        return of(IntStream.of(tags).mapToObj(Tag::ber).toArray(Tag[]::new));
    }

    public static TPath root() {
        return new TPath(List.of());
    }

    // --- fluent builder (immutable; each returns a fresh path) ---
    public TPath tag(final Tag t) {
        final var copy = new ArrayList<>(segments);
        copy.add(new Segment(t));
        return new TPath(copy);
    }

    public TPath tag(final int t) {
        return tag(Tag.ber(t));
    }

    // Narrow the last segment with a value predicate
    public TPath where(final Predicate<byte[]> valueMatch) {
        Objects.requireNonNull(valueMatch, "valueMatch");
        if (segments.isEmpty()) {
            throw new IllegalStateException("No segment to constrain");
        }
        final var copy = new ArrayList<>(segments);
        final var last = copy.size() - 1;
        copy.set(last, new Segment(copy.get(last).tag(), valueMatch));
        return new TPath(copy);
    }

    public List<Segment> segments() {
        return segments;
    }

    public boolean isEmpty() {
        return segments.isEmpty();
    }

    // --- the four operations: one core each (takes a path), the rest delegate ---

    // The single live node this path addresses: empty if absent, throws if a segment is ambiguous
    public static Optional<TLV> find(final List<TLV> roots, final TPath path) {
        var current = Optional.<TLV>empty();
        var level = roots;
        for (var seg : path.segments()) {
            final var matches = level.stream().filter(seg::matches).toList();
            if (matches.size() > 1) {
                throw new IllegalArgumentException("Multiple matches for tag " + seg.tag().toHex());
            }
            current = matches.stream().findFirst();
            if (current.isEmpty()) {
                return Optional.empty();
            }
            level = current.get().children();
        }
        return current;
    }

    // Every node matching the last segment, reached by taking the first match at each earlier segment.
    // An empty path or a broken spine yields an empty list. Returns live nodes; reads never copy.
    public static TLVs findAll(final List<TLV> roots, final TPath path) {
        if (path.isEmpty()) {
            return TLVs.of();
        }
        final var segs = path.segments();
        var level = roots;
        for (var i = 0; i < segs.size() - 1; i++) {
            final var match = level.stream().filter(segs.get(i)::matches).findFirst();
            if (match.isEmpty()) {
                return TLVs.of();
            }
            level = match.get().children();
        }
        final var last = segs.get(segs.size() - 1);
        return TLVs.of(level.stream().filter(last::matches).toList());
    }

    // Set the primitive value at the addressed leaf, creating missing path nodes along the way.
    // Throws if the addressed node is constructed (replacing a subtree is never silent).
    public static TLVs set(final List<TLV> roots, final TPath path, final byte[] value) {
        requireNonEmpty(path);
        Objects.requireNonNull(value, "value");
        final BiFunction<TLV, Tag, TLV> op = (matched, tag) -> {
            if (matched != null && matched.isConstructed()) {
                throw new IllegalArgumentException("Cannot set value on constructed tag " + tag.toHex());
            }
            return TLV.of(tag, value);
        };
        return TLVs.of(rebuild(roots, path.segments(), op));
    }

    // Append a child to the constructed parent named by the path, creating the chain if missing.
    public static TLVs add(final List<TLV> roots, final TPath path, final TLV child) {
        requireNonEmpty(path);
        Objects.requireNonNull(child, "child");
        final BiFunction<TLV, Tag, TLV> op = (matched, tag) -> {
            if (matched != null && !matched.isConstructed()) {
                throw new IllegalStateException("Cannot add child to primitive tag " + tag.toHex());
            }
            final var kids = new ArrayList<TLV>();
            if (matched != null) {
                for (var c : matched.children()) {
                    kids.add(copy(c));
                }
            }
            kids.add(copy(child));
            return TLV.of(tag, kids);
        };
        return TLVs.of(rebuild(roots, path.segments(), op));
    }

    // Drop the addressed node. An absent path is a no-op (a fresh copy is still returned).
    public static TLVs delete(final List<TLV> roots, final TPath path) {
        requireNonEmpty(path);
        if (find(roots, path).isEmpty()) {
            return TLVs.of(copyAll(roots));
        }
        final BiFunction<TLV, Tag, TLV> op = (matched, tag) -> null;
        return TLVs.of(rebuild(roots, path.segments(), op));
    }

    // --- sugar: fixed-arity for ops with a trailing value/child, varargs for the rest ---
    public static TLVs set(final List<TLV> roots, final int t0, final byte[] value) {
        return set(roots, of(t0), value);
    }

    public static TLVs set(final List<TLV> roots, final int t0, final int t1, final byte[] value) {
        return set(roots, of(t0, t1), value);
    }

    public static TLVs set(final List<TLV> roots, final int t0, final int t1, final int t2, final byte[] value) {
        return set(roots, of(t0, t1, t2), value);
    }

    public static TLVs add(final List<TLV> roots, final int t0, final TLV child) {
        return add(roots, of(t0), child);
    }

    public static TLVs add(final List<TLV> roots, final int t0, final int t1, final TLV child) {
        return add(roots, of(t0, t1), child);
    }

    public static TLVs add(final List<TLV> roots, final int t0, final int t1, final int t2, final TLV child) {
        return add(roots, of(t0, t1, t2), child);
    }

    public static TLVs delete(final List<TLV> roots, final int... tags) {
        return delete(roots, of(tags));
    }

    public static TLVs delete(final List<TLV> roots, final Tag... tags) {
        return delete(roots, of(tags));
    }

    public static Optional<TLV> find(final List<TLV> roots, final int... tags) {
        return find(roots, of(tags));
    }

    public static Optional<TLV> find(final List<TLV> roots, final Tag... tags) {
        return find(roots, of(tags));
    }

    public static TLVs findAll(final List<TLV> roots, final int... tags) {
        return findAll(roots, of(tags));
    }

    public static TLVs findAll(final List<TLV> roots, final Tag... tags) {
        return findAll(roots, of(tags));
    }

    // --- pure helpers ---

    // Rebuild one level: copy untouched siblings, descend at the first match, upsert an absent
    // segment. The leaf op returns the replacement node, or null to drop it.
    static List<TLV> rebuild(final List<TLV> level, final List<Segment> segs, final BiFunction<TLV, Tag, TLV> leaf) {
        final var seg = segs.get(0);
        final var last = segs.size() == 1;
        final var out = new ArrayList<TLV>(level.size());
        var done = false;
        for (var node : level) {
            if (!done && seg.matches(node)) {
                done = true;
                if (last) {
                    final var replacement = leaf.apply(node, seg.tag());
                    if (replacement != null) {
                        out.add(replacement);
                    }
                } else {
                    if (!node.isConstructed()) {
                        throw new IllegalStateException("Cannot descend into primitive tag " + seg.tag().toHex());
                    }
                    out.add(TLV.of(node.tag(), rebuild(node.children(), segs.subList(1, segs.size()), leaf)));
                }
            } else {
                out.add(copy(node));
            }
        }
        if (!done) {
            out.add(upsert(seg, segs, leaf));
        }
        return out;
    }

    // Create the missing branch down to the leaf; intermediates are empty constructed nodes.
    // Only ever reached for set and add, whose leaf operations always produce a node.
    static TLV upsert(final Segment seg, final List<Segment> segs, final BiFunction<TLV, Tag, TLV> leaf) {
        if (segs.size() == 1) {
            return leaf.apply(null, seg.tag());
        }
        return TLV.of(seg.tag(), List.of(upsert(segs.get(1), segs.subList(1, segs.size()), leaf)));
    }

    // Deep copy with no parent reference into the source tree, built from the library factories
    static TLV copy(final TLV node) {
        if (!node.isConstructed()) {
            return TLV.of(node.tag(), node.value());
        }
        return TLV.of(node.tag(), node.children().stream().map(TPath::copy).toList());
    }

    static List<TLV> copyAll(final List<TLV> roots) {
        return roots.stream().map(TPath::copy).toList();
    }

    static void requireNonEmpty(final TPath path) {
        if (path.isEmpty()) {
            throw new IllegalArgumentException("Path must not be empty");
        }
    }
}
