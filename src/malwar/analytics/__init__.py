"""Dashboard analytics — trends, heatmaps, timeline."""

from malwar.analytics.aggregator import AnalyticsAggregator
from malwar.analytics.heatmap import HeatmapGenerator
from malwar.analytics.trends import TrendAnalyzer

__all__ = [
    "AnalyticsAggregator",
    "HeatmapGenerator",
    "TrendAnalyzer",
]
