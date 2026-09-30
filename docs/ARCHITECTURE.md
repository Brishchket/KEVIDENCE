# Architecture Overview

## System Flow

```mermaid
flowchart TD
    subgraph Data Layer
        NVD[NVD API] --> P[Parser]
        EPSS[EPSS API] --> P
        KEV[CISA KEV] --> P
    end
    
    P --> Scorer[Deterministic Scorer\nFormula: CVSS + EPSS + KEV]
    Scorer --> DB[(SQLite DB)]
    
    subgraph Narrative Generation
        DB --> EB[Evidence Builder]
        EB --> LLM[LLM Client\nGemini/OpenAI/Anthropic]
        LLM --> N[Draft Narrative]
        
        EB --> V[Verbalizer\n1 Fact = 1 Sentence]
        V --> VF[Faithfulness Verifier]
        N --> VF
        
        VF --> |Low Score| Retry[Retry Loop]
        Retry --> LLM
        
        VF --> |High Score| Final[Final Narrative\n+ Confidence Label]
        Final --> DB
    end
```

## The Faithfulness Verifier

The verifier is the core defense against LLM hallucinations. It guarantees that the risk narrative is bounded by the ingested evidence.

```mermaid
flowchart TD
    N[Draft Narrative] --> Split[Sentence Tokenizer]
    E[Evidence JSON] --> V[Verbalizer] --> RS[Reference Sentences]
    
    Split --> Embed[Sentence-Transformers Embeddings]
    RS --> Embed
    
    Embed --> Cosine[Cosine Similarity Matrix]
    
    Cosine --> Max[Max Similarity per Sentence]
    
    Split --> FactCheck[Strict Facts Guard\nExtract Numbers, Dates, CVEs]
    E --> FactCheck
    
    Max --> Condition{Similarity >= 0.60\nAND\nFacts Match?}
    FactCheck --> Condition
    
    Condition --> |Yes| Supported[Supported]
    Condition --> |No| Flagged[Flagged]
```
