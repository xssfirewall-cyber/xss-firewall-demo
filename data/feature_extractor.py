
import numpy as np
import pandas as pd
import re
from typing import List, Dict, Tuple, Any
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
import logging
import pickle
from config.settings import DQNMAFSConfig


class XSSFeatureExtractor:
    """Advanced XSS feature extractor with customizable configuration."""

    def __init__(self, config: DQNMAFSConfig = None):
        """Initialize the feature extractor."""
        if config is None:
            from config.settings import get_config
            config = get_config()

        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

        self.vectorizers = {}
        self.feature_names = []
        self.feature_categories = {}
        self.is_fitted = False

        self._initialize_keyword_lists()

    def _initialize_keyword_lists(self):
        """Initialize specialized keyword lists."""
        self.event_handlers = [
            'onclick', 'onload', 'onmouseover', 'onerror', 'onkeydown',
            'onsubmit', 'onfocus', 'onblur', 'onchange', 'onselect',
            'onmouseout', 'onmousedown', 'onmouseup', 'ondblclick',
            'onkeyup', 'onkeypress', 'onresize', 'onscroll'
        ]

        self.js_functions = [
            'alert', 'prompt', 'confirm', 'eval', 'document.cookie',
            'window.location', 'document.write', 'innerHTML', 'outerHTML',
            'fromcharcode', 'unescape', 'escape', 'settimeout', 'setinterval',
            'xmlhttprequest', 'activexobject'
        ]

        self.html_tags = [
            'script', 'iframe', 'object', 'embed', 'applet', 'form',
            'input', 'textarea', 'select', 'img', 'link', 'meta'
        ]

        self.protocols = [
            'javascript:', 'data:', 'vbscript:', 'about:', 'file:',
            'ftp:', 'chrome:', 'moz-icon:'
        ]

        self.encoding_patterns = [
            r'&#x[0-9a-f]+;',  # Hex encoding
            r'&#\d+;',          # Decimal encoding
            r'%[0-9a-f]{2}',    # URL encoding
            r'\\u[0-9a-f]{4}',  # Unicode encoding
            r'\\x[0-9a-f]{2}'   # Hex escape
        ]

    def extract_pattern_features(self, text: str) -> Dict[str, float]:
        """Extract handcrafted pattern-based features from input text."""
        features = {}
        text_lower = text.lower()

        features.update(self._extract_script_features(text, text_lower))
        features.update(self._extract_event_features(text_lower))
        features.update(self._extract_js_features(text_lower))
        features.update(self._extract_html_features(text))
        features.update(self._extract_protocol_features(text_lower))
        features.update(self._extract_encoding_features(text))
        features.update(self._extract_character_features(text))
        features.update(self._extract_advanced_patterns(text_lower))

        return features

    def _extract_script_features(self, text: str, text_lower: str) -> Dict[str, float]:
        """Extract script tag features."""
        features = {
            'script_tag_count': float(text_lower.count('<script')),
            'script_close_count': float(text_lower.count('</script>')),
            'has_script_tag': float('<script' in text_lower),
            'has_script_close': float('</script>' in text_lower),
            'script_in_attributes': float('script:' in text_lower),
            'script_src_attribute': float('src=' in text_lower and 'script' in text_lower)
        }

        script_matches = re.findall(r'<script[^>]*>(.*?)</script>', text, re.DOTALL | re.IGNORECASE)
        features['script_content_length'] = float(sum(len(match) for match in script_matches))
        features['script_blocks_count'] = float(len(script_matches))
        return features

    def _extract_event_features(self, text_lower: str) -> Dict[str, float]:
        """Extract event handler features."""
        features = {}
        total_events = 0
        for handler in self.event_handlers:
            count = float(text_lower.count(handler))
            features[f'has_{handler}'] = float(handler in text_lower)
            features[f'{handler}_count'] = count
            total_events += count

        features['total_event_handlers'] = total_events
        features['unique_event_handlers'] = float(sum(1 for handler in self.event_handlers if handler in text_lower))
        return features

    def _extract_js_features(self, text_lower: str) -> Dict[str, float]:
        """Extract JavaScript function features."""
        features = {}
        total_js_functions = 0
        for func in self.js_functions:
            count = float(text_lower.count(func.lower()))
            features[f'has_{func.replace(".", "_")}'] = float(func.lower() in text_lower)
            features[f'{func.replace(".", "_")}_count'] = count
            total_js_functions += count

        features['total_js_functions'] = total_js_functions
        features['unique_js_functions'] = float(sum(1 for func in self.js_functions if func.lower() in text_lower))
        return features

    def _extract_html_features(self, text: str) -> Dict[str, float]:
        """Extract HTML structure features."""
        features = {}
        all_tags = re.findall(r'<[^>]+>', text)
        features['tag_count'] = float(len(all_tags))

        for tag in self.html_tags:
            pattern = f'<{tag}\\b'
            matches = re.findall(pattern, text, re.IGNORECASE)
            features[f'has_{tag}_tag'] = float(len(matches) > 0)
            features[f'{tag}_tag_count'] = float(len(matches))

        attributes = re.findall(r'\w+\s*=', text)
        features['attribute_count'] = float(len(attributes))
        features['malformed_tags'] = float(len(re.findall(r'<[^>]*<', text)))
        features['unclosed_tags'] = float(text.count('<') - text.count('>'))
        features['nested_quotes'] = float(text.count('"') + text.count("'"))
        features['style_attribute'] = float('style=' in text.lower())
        features['src_attribute'] = float('src=' in text.lower())
        features['href_attribute'] = float('href=' in text.lower())
        return features

    def _extract_protocol_features(self, text_lower: str) -> Dict[str, float]:
        """Extract protocol-based features."""
        features = {}
        for protocol in self.protocols:
            features[f'has_{protocol.replace(":", "")}'] = float(protocol in text_lower)
            features[f'{protocol.replace(":", "")}_count'] = float(text_lower.count(protocol))
        return features

    def _extract_encoding_features(self, text: str) -> Dict[str, float]:
        """Extract encoding pattern features."""
        features = {}
        features['has_hex_encoding'] = float(bool(re.search(self.encoding_patterns[0], text, re.I)))
        features['has_decimal_encoding'] = float(bool(re.search(self.encoding_patterns[1], text)))
        features['has_url_encoding'] = float(bool(re.search(self.encoding_patterns[2], text, re.I)))
        features['has_unicode_encoding'] = float(bool(re.search(self.encoding_patterns[3], text, re.I)))
        features['has_hex_escape'] = float(bool(re.search(self.encoding_patterns[4], text, re.I)))

        for i, pattern in enumerate(self.encoding_patterns):
            matches = re.findall(pattern, text, re.I)
            features[f'encoding_type_{i}_count'] = float(len(matches))

        features['has_html_entities'] = float('&amp;' in text or '&lt;' in text or '&gt;' in text)
        features['html_entities_count'] = float(len(re.findall(r'&\w+;', text)))
        return features

    def _extract_character_features(self, text: str) -> Dict[str, float]:
        """Extract character-level statistical features."""
        features = {}
        features['text_length'] = float(len(text))
        features['suspicious_chars'] = float(sum(text.count(c) for c in ['<', '>', '"', "'", ';', '&']))
        features['bracket_count'] = float(text.count('(') + text.count(')'))
        features['square_bracket_count'] = float(text.count('[') + text.count(']'))
        features['curly_bracket_count'] = float(text.count('{') + text.count('}'))
        features['equals_count'] = float(text.count('='))
        features['semicolon_count'] = float(text.count(';'))
        features['colon_count'] = float(text.count(':'))
        features['slash_count'] = float(text.count('/') + text.count('\\'))

        unique_chars = len(set(text))
        features['char_diversity'] = float(unique_chars / max(len(text), 1))

        if len(text) > 0:
            features['special_char_ratio'] = float(sum(1 for c in text if not c.isalnum()) / len(text))
            features['digit_ratio'] = float(sum(1 for c in text if c.isdigit()) / len(text))
            features['upper_ratio'] = float(sum(1 for c in text if c.isupper()) / len(text))
        else:
            features['special_char_ratio'] = 0.0
            features['digit_ratio'] = 0.0
            features['upper_ratio'] = 0.0
        return features

    def _extract_advanced_patterns(self, text_lower: str) -> Dict[str, float]:
        """Extract advanced XSS attack pattern features."""
        features = {
            'expression_usage': float('expression(' in text_lower),
            'import_usage': float('@import' in text_lower),
            'behavior_usage': float('behavior:' in text_lower),
            'binding_usage': float('binding:' in text_lower),
            'string_concat': float('+' in text_lower and ('string' in text_lower or 'char' in text_lower)),
            'fromcharcode_usage': float('fromcharcode' in text_lower),
            'eval_usage': float('eval(' in text_lower),
            'getelementbyid': float('getelementbyid' in text_lower),
            'getelementsbytagname': float('getelementsbytagname' in text_lower),
            'queryselector': float('queryselector' in text_lower),
            'document_cookie': float('document.cookie' in text_lower),
            'localstorage': float('localstorage' in text_lower),
            'sessionstorage': float('sessionstorage' in text_lower)
        }
        return features

    def extract_tfidf_features(self, sentences: List[str], fit: bool = True) -> np.ndarray:
        """Extract TF-IDF features for character and word n-grams."""
        if 'char_tfidf' not in self.vectorizers or fit:
            self.vectorizers['char_tfidf'] = TfidfVectorizer(
                max_features=self.config.MAX_CHAR_FEATURES,
                ngram_range=self.config.CHAR_NGRAM_RANGE,
                analyzer='char',
                lowercase=True
            )
            char_features = self.vectorizers['char_tfidf'].fit_transform(sentences).toarray()
        else:
            char_features = self.vectorizers['char_tfidf'].transform(sentences).toarray()

        if 'word_tfidf' not in self.vectorizers or fit:
            self.vectorizers['word_tfidf'] = TfidfVectorizer(
                max_features=self.config.MAX_WORD_FEATURES,
                ngram_range=self.config.WORD_NGRAM_RANGE,
                analyzer='word',
                lowercase=True,
                token_pattern=r'(?u)\b\w+\b|[<>/="\']+'
            )
            word_features = self.vectorizers['word_tfidf'].fit_transform(sentences).toarray()
        else:
            word_features = self.vectorizers['word_tfidf'].transform(sentences).toarray()

        return np.hstack([char_features, word_features])

    def extract_count_features(self, sentences: List[str], fit: bool = True) -> np.ndarray:
        """Extract keyword-based count features."""
        xss_keywords = [
            'script', 'alert', 'onclick', 'onload', 'javascript', 'eval',
            'document', 'window', 'onerror', 'prompt', 'confirm', 'cookie',
            'innerHTML', 'outerHTML', 'location', 'href'
        ]

        if 'count_vectorizer' not in self.vectorizers or fit:
            self.vectorizers['count_vectorizer'] = CountVectorizer(
                vocabulary=xss_keywords,
                lowercase=True
            )
            count_features = self.vectorizers['count_vectorizer'].fit_transform(sentences).toarray()
        else:
            count_features = self.vectorizers['count_vectorizer'].transform(sentences).toarray()

        return count_features

    def extract_all_features(self, sentences: List[str], fit: bool = True) -> Tuple[np.ndarray, List[str], Dict]:
        """Extract all features (TF-IDF, Count, and Pattern-based)."""
        self.logger.info("Starting feature extraction...")

        tfidf_features = self.extract_tfidf_features(sentences, fit)
        count_features = self.extract_count_features(sentences, fit)
        pattern_features = [list(self.extract_pattern_features(sentence).values()) for sentence in sentences]
        pattern_features = np.array(pattern_features)

        all_features = np.hstack([tfidf_features, count_features, pattern_features])

        if fit or not self.feature_names:
            self.feature_names = self._generate_feature_names(pattern_features.shape[1])
            self.feature_categories = self._categorize_features()

        self.is_fitted = True
        self.logger.info(f"Extracted {all_features.shape[1]} features from {len(sentences)} samples.")
        return all_features, self.feature_names, self.vectorizers

    def _generate_feature_names(self, n_pattern_features: int) -> List[str]:
        """Generate feature names."""
        feature_names = []
        if 'char_tfidf' in self.vectorizers:
            feature_names.extend(
                [f"char_tfidf_{i}" for i in range(len(self.vectorizers['char_tfidf'].get_feature_names_out()))]
            )
        if 'word_tfidf' in self.vectorizers:
            feature_names.extend(
                [f"word_tfidf_{i}" for i in range(len(self.vectorizers['word_tfidf'].get_feature_names_out()))]
            )
        if 'count_vectorizer' in self.vectorizers:
            feature_names.extend(
                [f"count_{word}" for word in self.vectorizers['count_vectorizer'].get_feature_names_out()]
            )

        sample_features = self.extract_pattern_features("")
        feature_names.extend(sample_features.keys())
        return feature_names

    def _categorize_features(self) -> Dict[str, List[int]]:
        """Categorize features by type."""
        categories = {
            'char_tfidf': [], 'word_tfidf': [], 'keyword_counts': [],
            'script_features': [], 'event_handlers': [], 'js_functions': [],
            'html_structure': [], 'protocols': [], 'encoding': [],
            'character_analysis': [], 'advanced_patterns': []
        }

        for i, name in enumerate(self.feature_names):
            if 'char_tfidf' in name:
                categories['char_tfidf'].append(i)
            elif 'word_tfidf' in name:
                categories['word_tfidf'].append(i)
            elif 'count_' in name:
                categories['keyword_counts'].append(i)
            elif 'script' in name or 'alert' in name:
                categories['script_features'].append(i)
            elif any(handler in name for handler in self.event_handlers):
                categories['event_handlers'].append(i)
            elif any(func.replace('.', '_') in name for func in self.js_functions):
                categories['js_functions'].append(i)
            elif any(tag in name for tag in ['tag', 'attribute', 'html']):
                categories['html_structure'].append(i)
            elif any(protocol.replace(':', '') in name for protocol in self.protocols):
                categories['protocols'].append(i)
            elif 'encoding' in name or 'hex' in name or 'unicode' in name:
                categories['encoding'].append(i)
            elif any(k in name for k in ['char', 'length', 'ratio', 'count']):
                categories['character_analysis'].append(i)
            else:
                categories['advanced_patterns'].append(i)
        return categories


def extract_xss_features(sentences: List[str], config: DQNMAFSConfig = None) -> Tuple[np.ndarray, List[str]]:
    """Convenience function to extract all XSS features quickly."""
    extractor = XSSFeatureExtractor(config)
    features, feature_names, _ = extractor.extract_all_features(sentences)
    return features, feature_names


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    test_sentences = [
        '<script>alert("XSS Attack!")</script>',
        '<img src="safe-image.jpg" alt="Safe content">',
        '<div onclick="maliciousFunction()">Click me</div>',
        'This is normal text content.',
        'javascript:alert(document.cookie)',
        '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>'
    ]

    print("Testing XSS Feature Extractor")
    print("=" * 50)

    try:
        extractor = XSSFeatureExtractor()
        features, feature_names, vectorizers = extractor.extract_all_features(test_sentences)
        print(f"Extracted {features.shape[1]} features from {len(test_sentences)} samples.")

        pattern_features = extractor.extract_pattern_features(test_sentences[0])
        important_features = {k: v for k, v in pattern_features.items() if v > 0}
        print("\nFirst sample analysis:")
        print(f"Text: {test_sentences[0]}")
        print(f"Important features: {important_features}")
        print("\n✅ Feature extractor test completed successfully!")

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)
