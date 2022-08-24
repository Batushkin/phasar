#pragma once

#include "phasar/Utils/TypeTraits.h"
#include "phasar/Utils/Utilities.h"

#include "llvm/ADT/None.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"

#include <concepts>
#include <string>
#include <type_traits>

namespace psr {

template <typename Graph> struct GraphTraits;

#if __cplusplus >= 202002L

template <typename Edge>
concept is_graph_edge = requires(const Edge e1, Edge e2) {
  { e1 == e2 } -> std::convertible_to<bool>;
  { e1 != e2 } -> std::convertible_to<bool>;
  { e1 < e2 } -> std::convertible_to<bool>;
};

template <typename GraphTrait>
concept is_graph_trait = requires(typename GraphTrait::graph_type &graph,
                                  const typename GraphTrait::graph_type &cgraph,
                                  typename GraphTrait::value_type val,
                                  typename GraphTrait::vertex_t vtx,
                                  typename GraphTrait::edge_t edge) {
  typename GraphTrait::graph_type;
  typename GraphTrait::value_type;
  typename GraphTrait::vertex_t;
  typename GraphTrait::edge_t;
  requires is_graph_edge<typename GraphTrait::edge_t>;
  { GraphTrait::Invalid } -> std::convertible_to<typename GraphTrait::vertex_t>;
  {
    GraphTrait::addNode(graph, val)
    } -> std::convertible_to<typename GraphTrait::vertex_t>;
  {GraphTrait::addEdge(graph, vtx, edge)};
  {
    GraphTrait::outEdges(cgraph, vtx)
    } -> psr::is_iterable_over_v<typename GraphTrait::edge_t>;
  { GraphTrait::outDegree(cgraph, vtx) } -> std::convertible_to<size_t>;
  {GraphTrait::dedupOutEdges(graph, vtx)};
  {
    GraphTrait::nodes(cgraph)
    } -> psr::is_iterable_over_v<typename GraphTrait::value_type>;
  {
    GraphTrait::node(cgraph, vtx)
    } -> std::convertible_to<typename GraphTrait::value_type>;
  { GraphTrait::size(cgraph) } -> std::convertible_to<size_t>;
  {GraphTrait::addRoot(graph, vtx)};
  {
    GraphTrait::roots(cgraph)
    } -> psr::is_iterable_over_v<typename GraphTrait::vertex_t>;
  { GraphTrait::pop(graph, vtx) } -> std::same_as<bool>;
  {
    GraphTrait::target(edge)
    } -> std::convertible_to<typename GraphTrait::vertex_t>;
  {
    GraphTrait::withEdgeTarget(edge, vtx)
    } -> std::convertible_to<typename GraphTrait::edge_t>;
};

template <typename Graph>
concept is_graph = requires(Graph g) {
  typename GraphTraits<std::decay_t<Graph>>;
  requires is_graph_trait<GraphTraits<std::decay_t<Graph>>>;
};

template <typename GraphTrait>
concept is_reservable_graph_trait_v = is_graph_trait<GraphTrait> &&
    requires(typename GraphTrait::graph_type &g) {
  {GraphTrait::reserve(g, size_t(0))};
};

#else
namespace detail {
template <typename GraphTrait, typename = void>
// NOLINTNEXTLINE(readability-identifier-naming)
struct is_reservable_graph_trait : std::false_type {};
template <typename GraphTrait>
struct is_reservable_graph_trait<
    GraphTrait,
    std::void_t<decltype(GraphTrait::reserve(
        std::declval<typename GraphTrait::graph_type &>(), size_t()))>>
    : std::true_type {};
} // namespace detail

template <typename GraphTrait>
// NOLINTNEXTLINE(readability-identifier-naming)
static constexpr bool is_reservable_graph_trait_v =
    detail::is_reservable_graph_trait<GraphTrait>::value;
#endif

template <typename GraphTy>
std::decay_t<GraphTy> reverseGraph(GraphTy &&G)
#if __cplusplus >= 202002L
    requires is_graph<GraphTy>
#endif
{
  std::decay_t<GraphTy> Ret;
  using traits_t = GraphTraits<std::decay_t<GraphTy>>;
  if constexpr (is_reservable_graph_trait_v<traits_t>) {
    traits_t::reserve(Ret, traits_t::size(G));
  }

  for (auto &Nod : traits_t::nodes(G)) {
    /// NOTE: in case of a const reference, nod will be const as well preventing
    /// moving
    traits_t::addNode(Ret, std::move(Nod));
  }

  for (size_t I = 0, End = traits_t::size(G); I != End; ++I) {
    for (auto Child : traits_t::outEdges(G, I)) {
      traits_t::addEdge(Ret, traits_t::target(Child),
                        traits_t::withEdgeTarget(Child, I));
    }
    if (traits_t::outDegree(G, I) == 0) {
      traits_t::addRoot(Ret, I);
    }
  }
  return Ret;
}

template <typename GraphTy>
void printGraph(const GraphTy &G, llvm::raw_ostream &OS,
                llvm::StringRef Name = "")
#if __cplusplus >= 202002L
    requires is_graph<GraphTy>
#endif
{
  using traits_t = GraphTraits<GraphTy>;

  OS << "digraph " << Name << " {\n";
  psr::scope_exit CloseBrace = [&OS] { OS << "}\n"; };

  auto Sz = traits_t::size(G);
  std::string Buf;

  for (size_t I = 0; I < Sz; ++I) {
    OS << I;
    if constexpr (!std::is_same_v<llvm::NoneType,
                                  typename traits_t::value_type>) {
      OS << "[label=\"";

      Buf.clear();
      llvm::raw_string_ostream ROS(Buf);
      ROS << traits_t::node(G, I);
      OS.write_escaped(ROS.str());
      OS << "\"]";
    }
    OS << ";\n";
    for (const auto &Edge : traits_t::outEdges(G, I)) {
      OS << I << "->" << Edge << ";\n";
    }
  }
}

} // namespace psr