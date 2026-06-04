from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.region import Region
from xrefer._vendor.ascii_graphs.common.dimension import Dimension


class QuadTree:
    """Port of QuadTree from QuadTree.scala. Stores HasRegion items."""

    MAX_CAPACITY = 1

    def __init__(self, dimension: Dimension):
        self._dimension = dimension
        all_region = Region(Point(0, 0), Point(dimension.height - 1, dimension.width - 1))
        self._root = _LeafNode(all_region, set())

    def add(self, t):
        self._root = self._add_rec(self._root, t)

    def remove(self, t):
        self._root = self._remove_rec(self._root, t)

    def _add_rec(self, node, t):
        region = t.region if hasattr(t, 'region') else t
        assert node.region.contains(region), f"{region} not in {node.region}"
        if isinstance(node, _QuadNode):
            for i, child in enumerate(node.children):
                if child.region.contains(region):
                    new_children = list(node.children)
                    new_children[i] = self._add_rec(child, t)
                    return _QuadNode(node.region, node.items, new_children)
            return _QuadNode(node.region, node.items | {t}, node.children)
        else:  # LeafNode
            new_items = node.items | {t}
            if len(new_items) <= self.MAX_CAPACITY and node.region.width > 1 and node.region.height > 1:
                return _LeafNode(node.region, new_items)
            else:
                return self._quadrate(_LeafNode(node.region, new_items))

    def _remove_rec(self, node, t):
        region = t.region if hasattr(t, 'region') else t
        if isinstance(node, _QuadNode):
            for i, child in enumerate(node.children):
                if child.region.contains(region):
                    new_children = list(node.children)
                    new_children[i] = self._remove_rec(child, t)
                    return _QuadNode(node.region, node.items, new_children)
            return _QuadNode(node.region, node.items - {t}, node.children)
        else:
            return _LeafNode(node.region, node.items - {t})

    def _quadrate(self, leaf: _LeafNode) -> _QuadNode:
        tl, tr, bl, br = self._split_region(leaf.region)

        def make_leaf(quadrant):
            items = {i for i in leaf.items if quadrant.contains(i.region if hasattr(i, 'region') else i)}
            return _LeafNode(quadrant, items)

        tl_node = make_leaf(tl)
        tr_node = make_leaf(tr)
        bl_node = make_leaf(bl)
        br_node = make_leaf(br)

        children = [tl_node, tr_node, bl_node, br_node]
        child_items = {i for child in children for i in child.items}
        new_items = leaf.items - child_items
        return _QuadNode(leaf.region, new_items, children)

    def _split_region(self, region: Region):
        middle_top = region.top_left.right(region.width // 2)
        middle_left = region.top_left.down(region.height // 2)
        middle_right = region.top_right.down(region.height // 2)
        middle_bottom = region.bottom_left.right(region.width // 2)
        middle = middle_top.down(region.height // 2)

        tl = Region(region.top_left, middle.up().left())
        br = Region(middle, region.bottom_right)
        bl = Region(middle_left, middle_bottom.left())
        tr = Region(middle_top, middle_right.up())
        return tl, tr, bl, br

    def collides(self, region: Region) -> bool:
        return self._collides(region, self._root)

    def _collides(self, region: Region, node) -> bool:
        if not region.intersects(node.region):
            return False
        if node.immediate_item_intersects(region):
            return True
        return any(self._collides(region, child) for child in node.children)

    def collisions(self, t) -> set:
        region = t.region if hasattr(t, 'region') else t
        return self._collect_collisions(region, self._root)

    def _collect_collisions(self, region: Region, node) -> set:
        if not region.intersects(node.region):
            return set()
        result = node.immediate_items_intersecting(region)
        for child in node.children:
            result |= self._collect_collisions(region, child)
        return result


class _Node:
    def __init__(self, region: Region, items: set):
        self.region = region
        self.items = items

    def immediate_items_intersecting(self, region: Region) -> set:
        return {i for i in self.items
                if getattr(i, 'region', i).intersects(region)}

    def immediate_item_intersects(self, region: Region) -> bool:
        return any(getattr(i, 'region', i).intersects(region)
                   for i in self.items)

    @property
    def children(self):
        return []


class _LeafNode(_Node):
    pass


class _QuadNode(_Node):
    def __init__(self, region: Region, items: set, children: list):
        super().__init__(region, items)
        self._children = children

    @property
    def children(self):
        return self._children
