"""
Enhanced Configuration Module for GNN-DQN-MAFS System
======================================================
Provides flexible, scalable configuration with support for:
- Large dataset handling
- Per-agent memory tracking
- Dynamic resource allocation
- Academic-grade evaluation settings
"""

import os
import json
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class DatasetSize(Enum):
    """Dataset size categories for automatic configuration."""
    SMALL = "small"      # < 10,000 samples
    MEDIUM = "medium"    # 10,000 - 100,000 samples
    LARGE = "large"      # 100,000 - 1,000,000 samples
    XLARGE = "xlarge"    # > 1,000,000 samples


class MemoryProfile(Enum):
    """Memory usage profiles."""
    LOW = "low"          # < 4GB RAM
    MEDIUM = "medium"    # 4-8GB RAM
    HIGH = "high"        # 8-16GB RAM
    UNLIMITED = "unlimited"  # > 16GB RAM


@dataclass
class AgentConfig:
    """Configuration for individual agents."""
    agent_id: int
    specialization: str
    feature_indices: List[int] = field(default_factory=list)
    learning_rate_multiplier: float = 1.0
    exploration_bonus: float = 0.0
    memory_limit_mb: float = 100.0
    priority_level: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            'agent_id': self.agent_id,
            'specialization': self.specialization,
            'feature_indices': self.feature_indices,
            'learning_rate_multiplier': self.learning_rate_multiplier,
            'exploration_bonus': self.exploration_bonus,
            'memory_limit_mb': self.memory_limit_mb,
            'priority_level': self.priority_level
        }


@dataclass
class MemoryConfig:
    """Memory management configuration."""
    max_replay_buffer_mb: float = 500.0
    max_agent_memory_mb: float = 100.0
    gc_threshold_percent: float = 80.0
    enable_memory_monitoring: bool = True
    monitoring_interval_episodes: int = 5
    auto_cleanup: bool = True
    checkpoint_memory_threshold_mb: float = 1000.0

    def get_buffer_size_for_memory(self, state_size: int, max_memory_mb: float = None) -> int:
        """Calculate optimal buffer size based on memory constraints."""
        if max_memory_mb is None:
            max_memory_mb = self.max_replay_buffer_mb

        # Experience size: 2 states + action + reward + done
        experience_size_bytes = (state_size * 8 * 2) + 4 + 8 + 1
        overhead_factor = 1.5  # Account for Python object overhead

        max_experiences = int((max_memory_mb * 1024 * 1024) / (experience_size_bytes * overhead_factor))
        return max(1000, min(max_experiences, 100000))


@dataclass
class EvaluationConfig:
    """Academic evaluation configuration."""
    # Statistical testing
    enable_statistical_tests: bool = True
    confidence_level: float = 0.95
    bootstrap_iterations: int = 1000
    cross_validation_folds: int = 5

    # Metrics
    primary_metric: str = "f1_score"
    secondary_metrics: List[str] = field(default_factory=lambda: [
        "accuracy", "precision", "recall", "detection_rate",
        "false_positive_rate", "mcc", "roc_auc"
    ])

    # Visualization
    plot_dpi: int = 300
    plot_format: str = "pdf"
    use_latex_fonts: bool = True
    color_scheme: str = "academic"  # academic, colorblind, grayscale
    figure_width_inches: float = 8.0
    figure_height_inches: float = 6.0

    # Reporting
    generate_latex_tables: bool = True
    decimal_places: int = 4
    include_confidence_intervals: bool = True


@dataclass
class LargeDataConfig:
    """Configuration for handling large datasets."""
    enable_streaming: bool = True
    chunk_size: int = 5000
    prefetch_chunks: int = 2
    use_memory_mapping: bool = True
    compression: str = "gzip"  # None, gzip, lz4
    cache_preprocessed: bool = True
    cache_dir: str = "cache/"
    max_cache_size_gb: float = 10.0
    parallel_preprocessing: bool = True
    num_workers: int = 4

    def get_optimal_chunk_size(self, total_samples: int, available_memory_mb: float) -> int:
        """Calculate optimal chunk size based on data and memory."""
        if total_samples < 10000:
            return total_samples

        # Estimate memory per sample (conservative)
        estimated_sample_memory_kb = 10  # Adjust based on feature count
        max_samples_in_memory = int((available_memory_mb * 1024) / estimated_sample_memory_kb)

        optimal_chunk = min(max_samples_in_memory // 2, total_samples // 10)
        return max(1000, min(optimal_chunk, 50000))


@dataclass
class DQNMAFSConfig:
    """
    Enhanced DQN-MAFS Configuration with support for:
    - Large datasets
    - Per-agent memory tracking
    - Flexible evaluation
    - Academic-grade visualization
    """

    # ===============================
    # Basic DQN hyperparameters
    # ===============================
    LEARNING_RATE: float = 0.001
    GAMMA: float = 0.995
    EPSILON_START: float = 0.97
    EPSILON_DECAY: float = 0.995
    EPSILON_MIN: float = 0.01

    # ===============================
    # Replay buffer & training
    # ===============================
    REPLAY_BUFFER_SIZE: int = 10000
    BATCH_SIZE: int = 32
    TARGET_UPDATE_FREQUENCY: int = 10
    MIN_REPLAY_SIZE: int = 1000
    USE_DOUBLE_DQN: bool = True
    USE_PRIORITIZED_REPLAY: bool = False
    PRIORITY_ALPHA: float = 0.6
    PRIORITY_BETA: float = 0.4

    # ===============================
    # Multi-agent system
    # ===============================
    NUM_AGENTS: int = 10
    CHUNK_SIZE: int = 1000
    MAX_EPISODES: int = 50
    AGENT_COOPERATION_MODE: str = "independent"  # independent, cooperative, competitive

    # ===============================
    # FARD-DFS parameters
    # ===============================
    REWARD_METHODS: List[str] = None
    DEFAULT_REWARD_METHOD: str = "ACC"
    SLIDING_WINDOW_SIZE: int = 4
    ACCURACY_THRESHOLD: float = 0.6

    # Reward weights
    PERFORMANCE_WEIGHT: float = 150.0
    DETECTION_WEIGHT: float = 50.0
    FP_PENALTY_WEIGHT: float = 100.0
    SPARSITY_WEIGHT: float = 0.1
    IMPORTANCE_WEIGHT: float = 30.0
    STABILITY_PENALTY: float = 0.5
    EFFICIENCY_BONUS: float = 20.0

    # ===============================
    # Neural network
    # ===============================
    HIDDEN_LAYERS: List[int] = None
    DROPOUT_RATE: float = 0.3
    ACTIVATION: str = 'relu'
    OUTPUT_ACTIVATION: str = 'linear'
    USE_BATCH_NORMALIZATION: bool = False
    L2_REGULARIZATION: float = 0.0001

    # ===============================
    # Feature extraction
    # ===============================
    MAX_CHAR_FEATURES: int = 150
    MAX_WORD_FEATURES: int = 100
    CHAR_NGRAM_RANGE: tuple = (2, 4)
    WORD_NGRAM_RANGE: tuple = (1, 2)

    # ===============================
    # Data split
    # ===============================
    TEST_SIZE: float = 0.2
    VALIDATION_SIZE: float = 0.1
    RANDOM_STATE: int = 42
    STRATIFIED_SPLIT: bool = True

    # ===============================
    # Logging & evaluation
    # ===============================
    PRINT_INTERVAL: int = 1
    SAVE_INTERVAL: int = 10
    EARLY_STOPPING_PATIENCE: int = 20
    MIN_IMPROVEMENT: float = 0.001
    VERBOSE_LOGGING: bool = True
    LOG_LEVEL: str = "INFO"

    # ===============================
    # Paths
    # ===============================
    DATA_PATH: str = "data/"
    MODEL_PATH: str = "models/"
    RESULTS_PATH: str = "results/"
    LOGS_PATH: str = "logs/"
    PLOTS_PATH: str = "results/plots/"
    CHECKPOINTS_PATH: str = "results/checkpoints/"

    # ===============================
    # Agent configurations
    # ===============================
    AGENT_SPECIALIZATIONS: Dict[int, str] = None
    AGENT_CONFIGS: List[AgentConfig] = None

    # ===============================
    # Sub-configurations
    # ===============================
    memory_config: MemoryConfig = None
    evaluation_config: EvaluationConfig = None
    large_data_config: LargeDataConfig = None

    # ===============================
    # Classifiers
    # ===============================
    AVAILABLE_CLASSIFIERS: List[str] = None
    DEFAULT_CLASSIFIER: str = "DecisionTree"

    def __post_init__(self):
        """Initialize complex defaults and sub-configurations."""
        # Initialize lists
        if self.REWARD_METHODS is None:
            self.REWARD_METHODS = ['ACC', 'ALC', 'IM', 'OA-OT']

        if self.HIDDEN_LAYERS is None:
            self.HIDDEN_LAYERS = [128, 64, 32]

        if self.AVAILABLE_CLASSIFIERS is None:
            self.AVAILABLE_CLASSIFIERS = [
                "DecisionTree", "RandomForest", "SVM",
                "KNN", "LogisticRegression", "GradientBoosting"
            ]

        # Initialize agent specializations
        if self.AGENT_SPECIALIZATIONS is None:
            self.AGENT_SPECIALIZATIONS = {
                0: "Script & Code Injection Detection",
                1: "Event Handler Analysis",
                2: "Protocol & URL Security",
                3: "Character Pattern Recognition",
                4: "Encoding & Obfuscation Detection",
                5: "HTML Structure Analysis"
            }

        # Initialize sub-configurations
        if self.memory_config is None:
            self.memory_config = MemoryConfig()

        if self.evaluation_config is None:
            self.evaluation_config = EvaluationConfig()

        if self.large_data_config is None:
            self.large_data_config = LargeDataConfig()

        # Initialize agent configs
        if self.AGENT_CONFIGS is None:
            self.AGENT_CONFIGS = self._create_default_agent_configs()

        # Create directories
        self._create_directories()

    def _create_default_agent_configs(self) -> List[AgentConfig]:
        """Create default configuration for each agent."""
        configs = []
        for i in range(self.NUM_AGENTS):
            specialization = self.AGENT_SPECIALIZATIONS.get(
                i, f"General Agent {i}"
            )
            configs.append(AgentConfig(
                agent_id=i,
                specialization=specialization,
                memory_limit_mb=self.memory_config.max_agent_memory_mb
            ))
        return configs

    def _create_directories(self):
        """Create required directories."""
        directories = [
            self.DATA_PATH,
            self.MODEL_PATH,
            self.RESULTS_PATH,
            self.LOGS_PATH,
            self.PLOTS_PATH,
            self.CHECKPOINTS_PATH,
            self.large_data_config.cache_dir
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def configure_for_dataset_size(self, num_samples: int, num_features: int):
        """Auto-configure based on dataset size."""
        # Determine dataset category
        if num_samples < 10000:
            size_category = DatasetSize.SMALL
        elif num_samples < 100000:
            size_category = DatasetSize.MEDIUM
        elif num_samples < 1000000:
            size_category = DatasetSize.LARGE
        else:
            size_category = DatasetSize.XLARGE

        logging.info(f"Auto-configuring for {size_category.value} dataset: "
                     f"{num_samples} samples, {num_features} features")

        # Adjust configurations
        if size_category == DatasetSize.SMALL:
            self.CHUNK_SIZE = num_samples
            self.BATCH_SIZE = min(32, num_samples // 10)
            self.large_data_config.enable_streaming = False

        elif size_category == DatasetSize.MEDIUM:
            self.CHUNK_SIZE = 5000
            self.BATCH_SIZE = 64
            self.REPLAY_BUFFER_SIZE = 20000

        elif size_category == DatasetSize.LARGE:
            self.CHUNK_SIZE = 10000
            self.BATCH_SIZE = 128
            self.REPLAY_BUFFER_SIZE = 50000
            self.large_data_config.enable_streaming = True
            self.large_data_config.parallel_preprocessing = True

        else:  # XLARGE
            self.CHUNK_SIZE = 20000
            self.BATCH_SIZE = 256
            self.REPLAY_BUFFER_SIZE = 100000
            self.large_data_config.enable_streaming = True
            self.large_data_config.use_memory_mapping = True
            self.large_data_config.compression = "lz4"

        # Adjust network size based on features
        if num_features < 100:
            self.HIDDEN_LAYERS = [64, 32]
        elif num_features < 500:
            self.HIDDEN_LAYERS = [128, 64, 32]
        else:
            self.HIDDEN_LAYERS = [256, 128, 64]

        return self

    def configure_memory_profile(self, profile: MemoryProfile):
        """Configure based on available system memory."""
        if profile == MemoryProfile.LOW:
            self.REPLAY_BUFFER_SIZE = 5000
            self.BATCH_SIZE = 16
            self.memory_config.max_replay_buffer_mb = 100
            self.memory_config.max_agent_memory_mb = 25
            self.large_data_config.chunk_size = 1000

        elif profile == MemoryProfile.MEDIUM:
            self.REPLAY_BUFFER_SIZE = 10000
            self.BATCH_SIZE = 32
            self.memory_config.max_replay_buffer_mb = 250
            self.memory_config.max_agent_memory_mb = 50

        elif profile == MemoryProfile.HIGH:
            self.REPLAY_BUFFER_SIZE = 50000
            self.BATCH_SIZE = 64
            self.memory_config.max_replay_buffer_mb = 500
            self.memory_config.max_agent_memory_mb = 100

        else:  # UNLIMITED
            self.REPLAY_BUFFER_SIZE = 100000
            self.BATCH_SIZE = 128
            self.memory_config.max_replay_buffer_mb = 2000
            self.memory_config.max_agent_memory_mb = 250

        # Update agent configs
        for agent_config in self.AGENT_CONFIGS:
            agent_config.memory_limit_mb = self.memory_config.max_agent_memory_mb

        return self

    def get_agent_config(self, agent_id: int) -> AgentConfig:
        """Get configuration for specific agent."""
        for config in self.AGENT_CONFIGS:
            if config.agent_id == agent_id:
                return config
        return None

    def update_agent_config(self, agent_id: int, **kwargs):
        """Update configuration for specific agent."""
        config = self.get_agent_config(agent_id)
        if config:
            for key, value in kwargs.items():
                if hasattr(config, key):
                    setattr(config, key, value)

    def get_agent_feature_assignment(self) -> Dict[int, List[str]]:
        """Map agents to feature groups based on specialization."""
        return {
            0: ['script', 'alert', 'eval', 'document.write', 'innerHTML'],
            1: ['onclick', 'onload', 'onerror', 'onmouseover', 'onkeydown'],
            2: ['javascript:', 'data:', 'vbscript:', 'about:', 'protocol'],
            3: ['char_tfidf', 'suspicious_chars', 'bracket_count'],
            4: ['encoding', 'hex', 'unicode', 'escape', 'unescape'],
            5: ['tag_count', 'attribute', 'malformed', 'structure']
        }

    def get_reward_method_config(self, method: str) -> Dict[str, Any]:
        """Return per-method configuration for reward computation."""
        configs = {
            "ACC": {
                "window_size": self.SLIDING_WINDOW_SIZE,
                "threshold": self.ACCURACY_THRESHOLD,
                "discount_factor": 0.9
            },
            "ALC": {
                "softmax_temperature": 1.0,
                "change_sensitivity": 0.5
            },
            "IM": {
                "n_estimators": 50,
                "max_depth": None,
                "random_state": self.RANDOM_STATE
            },
            "OA-OT": {
                "hamming_distance": 1,
                "strict_constraint": True
            },
        }
        return configs.get(method, {})

    def validate_config(self) -> bool:
        """Validate configuration values."""
        errors = []

        if self.LEARNING_RATE <= 0 or self.LEARNING_RATE > 1:
            errors.append("LEARNING_RATE must be in (0, 1].")

        if not (0 <= self.GAMMA <= 1):
            errors.append("GAMMA must be in [0, 1].")

        if self.EPSILON_START < self.EPSILON_MIN:
            errors.append("EPSILON_START must be >= EPSILON_MIN.")

        if self.BATCH_SIZE > self.REPLAY_BUFFER_SIZE:
            errors.append("BATCH_SIZE must be <= REPLAY_BUFFER_SIZE.")

        if self.NUM_AGENTS <= 0:
            errors.append("NUM_AGENTS must be > 0.")

        valid_methods = ['ACC', 'ALC', 'IM', 'OA-OT']
        for method in self.REWARD_METHODS:
            if method not in valid_methods:
                errors.append(f"Unsupported reward method: {method}")

        if errors:
            logging.error("Configuration errors:")
            for error in errors:
                logging.error(f"  - {error}")
            return False

        return True

    def save_config(self, filepath: str):
        """Save configuration to JSON file."""
        config_dict = self._to_serializable_dict()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config_dict, f, indent=2, ensure_ascii=False)

    def _to_serializable_dict(self) -> Dict[str, Any]:
        """Convert config to JSON-serializable dictionary."""
        result = {}
        for key, value in self.__dict__.items():
            if key.startswith('_'):
                continue
            if isinstance(value, (MemoryConfig, EvaluationConfig, LargeDataConfig)):
                result[key] = value.__dict__
            elif isinstance(value, list) and value and isinstance(value[0], AgentConfig):
                result[key] = [ac.to_dict() for ac in value]
            elif isinstance(value, Enum):
                result[key] = value.value
            else:
                result[key] = value
        return result

    @classmethod
    def load_config(cls, filepath: str) -> 'DQNMAFSConfig':
        """Load configuration from JSON file."""
        with open(filepath, 'r', encoding='utf-8') as f:
            config_dict = json.load(f)

        # Handle nested configs
        if 'memory_config' in config_dict and isinstance(config_dict['memory_config'], dict):
            config_dict['memory_config'] = MemoryConfig(**config_dict['memory_config'])
        if 'evaluation_config' in config_dict and isinstance(config_dict['evaluation_config'], dict):
            config_dict['evaluation_config'] = EvaluationConfig(**config_dict['evaluation_config'])
        if 'large_data_config' in config_dict and isinstance(config_dict['large_data_config'], dict):
            config_dict['large_data_config'] = LargeDataConfig(**config_dict['large_data_config'])

        # Handle agent configs
        if 'AGENT_CONFIGS' in config_dict and isinstance(config_dict['AGENT_CONFIGS'], list):
            config_dict['AGENT_CONFIGS'] = [
                AgentConfig(**ac) if isinstance(ac, dict) else ac
                for ac in config_dict['AGENT_CONFIGS']
            ]

        return cls(**config_dict)

    def get_network_architecture(self) -> Dict[str, Any]:
        """Return network architecture summary."""
        return {
            "hidden_layers": self.HIDDEN_LAYERS,
            "dropout_rate": self.DROPOUT_RATE,
            "activation": self.ACTIVATION,
            "output_activation": self.OUTPUT_ACTIVATION,
            "learning_rate": self.LEARNING_RATE,
            "use_batch_norm": self.USE_BATCH_NORMALIZATION,
            "l2_regularization": self.L2_REGULARIZATION
        }

    def get_training_config(self) -> Dict[str, Any]:
        """Return training configuration summary."""
        return {
            "max_episodes": self.MAX_EPISODES,
            "batch_size": self.BATCH_SIZE,
            "replay_buffer_size": self.REPLAY_BUFFER_SIZE,
            "target_update_frequency": self.TARGET_UPDATE_FREQUENCY,
            "use_double_dqn": self.USE_DOUBLE_DQN,
            "use_prioritized_replay": self.USE_PRIORITIZED_REPLAY,
            "epsilon_config": {
                "start": self.EPSILON_START,
                "decay": self.EPSILON_DECAY,
                "min": self.EPSILON_MIN
            }
        }

    def __str__(self) -> str:
        """Human-readable summary."""
        return f"""
{'='*60}
DQN-MAFS Enhanced Configuration
{'='*60}

DQN Parameters:
  - Learning Rate: {self.LEARNING_RATE}
  - Gamma: {self.GAMMA}
  - Epsilon: {self.EPSILON_START} -> {self.EPSILON_MIN}
  - Double DQN: {self.USE_DOUBLE_DQN}

Multi-Agent System:
  - Agents: {self.NUM_AGENTS}
  - Episodes: {self.MAX_EPISODES}
  - Chunk Size: {self.CHUNK_SIZE}
  - Cooperation Mode: {self.AGENT_COOPERATION_MODE}

Network Architecture:
  - Hidden Layers: {self.HIDDEN_LAYERS}
  - Dropout: {self.DROPOUT_RATE}
  - Activation: {self.ACTIVATION}

Memory Configuration:
  - Max Replay Buffer: {self.memory_config.max_replay_buffer_mb} MB
  - Max Agent Memory: {self.memory_config.max_agent_memory_mb} MB
  - Memory Monitoring: {self.memory_config.enable_memory_monitoring}

Large Data Configuration:
  - Streaming: {self.large_data_config.enable_streaming}
  - Chunk Size: {self.large_data_config.chunk_size}
  - Memory Mapping: {self.large_data_config.use_memory_mapping}

FARD-DFS:
  - Methods: {self.REWARD_METHODS}
  - Default: {self.DEFAULT_REWARD_METHOD}
{'='*60}
"""


# Default instance
default_config = DQNMAFSConfig()


def get_config() -> DQNMAFSConfig:
    """Return the default configuration instance."""
    return default_config


def create_custom_config(**kwargs) -> DQNMAFSConfig:
    """Create a configuration instance with custom overrides."""
    return DQNMAFSConfig(**kwargs)


def create_config_for_dataset(num_samples: int, num_features: int,
                               memory_profile: str = "medium") -> DQNMAFSConfig:
    """Create optimized configuration for specific dataset."""
    config = DQNMAFSConfig()
    config.configure_for_dataset_size(num_samples, num_features)
    config.configure_memory_profile(MemoryProfile(memory_profile))
    return config


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("Testing Enhanced Configuration System")
    print("=" * 60)

    # Test basic config
    config = DQNMAFSConfig()
    print(config)

    # Test auto-configuration for large dataset
    config2 = create_config_for_dataset(500000, 300, "high")
    print("\nAuto-configured for large dataset:")
    print(f"  Chunk Size: {config2.CHUNK_SIZE}")
    print(f"  Batch Size: {config2.BATCH_SIZE}")
    print(f"  Hidden Layers: {config2.HIDDEN_LAYERS}")

    # Test validation
    if config.validate_config():
        print("\nConfiguration is valid.")

    # Test save/load
    config.save_config("config/config_test.json")
    loaded = DQNMAFSConfig.load_config("config/config_test.json")
    print(f"\nLoaded config agents: {loaded.NUM_AGENTS}")

    print("\nConfiguration system test completed successfully!")
