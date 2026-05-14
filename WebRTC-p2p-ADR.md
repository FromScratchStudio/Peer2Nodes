# ADR — WebRTC peer-to-peer transport (Option B)

**Date:** 2026-05-14  
**Status:** Implemented (runtime building blocks)

## 1. Contexte

La simulation actuelle repose sur un bus mémoire local à une page.  
Ce modèle ne permet pas la communication entre deux navigateurs sur deux machines différentes.

Pour supporter un mode réellement distribuable, il faut:

1. un transport P2P réel (WebRTC DataChannel) pour les messages applicatifs,
2. un canal de signalisation pour échanger `offer` / `answer` / `candidate` pendant la négociation.

## 2. Décision

Implémenter une base WebRTC P2P commune sur les trois runtimes (JS, iOS, Kotlin), en gardant:

- le `PeerNodeClient` et le protocole métier inchangés,
- un remplacement propre au niveau de l’abstraction `PeerTransport`.

## 3. Ce qui a été ajouté

### 3.1 JavaScript

Fichiers:

- `/home/runner/work/Peer2Nodes/Peer2Nodes/javascript/webrtc-p2p.js`
- `/home/runner/work/Peer2Nodes/Peer2Nodes/javascript/signaling-server.js`

Contenu:

- `WebRTCPeerTransport`: transport `PeerTransport` basé sur `RTCPeerConnection` + `RTCDataChannel`.
- `HttpPollingSignaling`: client de signalisation HTTP (publish + long polling).
- `SignalType`: types de signal (`offer`, `answer`, `candidate`).
- Serveur de signalisation minimal (Node.js `http`, sans dépendance externe) pour relayer les signaux entre pairs.

Le transport WebRTC sérialise les `PeerEnvelope` en JSON sur DataChannel; après établissement du canal, les payloads ne transitent plus par le serveur.

### 3.2 iOS (Swift)

Fichier:

- `/home/runner/work/Peer2Nodes/Peer2Nodes/ios/Sources/Peer2Nodes/WebRTCPeerTransport.swift`

Contenu:

- `WebRTCSignalType`, `WebRTCSignal`
- `WebRTCSignalingClient` (abstraction signalisation)
- `WebRTCEngine` (abstraction moteur WebRTC natif)
- `WebRTCPeerTransport` (implémente `PeerTransport`)

Le transport orchestre le flux offer/answer/candidate et reste découplé de la librairie WebRTC choisie par l’app.

### 3.3 Android/Kotlin

Fichier:

- `/home/runner/work/Peer2Nodes/Peer2Nodes/android/src/main/java/com/fromscratchstudio/peer2nodes/WebRTCPeerTransport.kt`

Contenu:

- `WebRTCSignalType`, `WebRTCSignal`
- `WebRTCSignalingClient`, `WebRTCEngine`, `PeerEnvelopeCodec`
- `WebRTCPeerTransport` (implémente `PeerTransport`)

Même séparation des responsabilités que sur iOS: orchestration transport d’un côté, implémentation moteur/signaling de l’autre.

## 4. Principes de clean code appliqués

- **Single Responsibility**: transport, signalisation, moteur WebRTC séparés.
- **Dependency Inversion**: iOS/Kotlin dépendent d’interfaces (`WebRTCEngine`, `WebRTCSignalingClient`), pas d’implémentations concrètes.
- **Open/Closed**: possibilité de brancher un autre backend de signalisation sans toucher `PeerNodeClient`.
- **Lisibilité**: conventions de nommage homogènes entre JS / Swift / Kotlin.

## 5. Flux opérationnel

1. Le pair A veut parler à B ⇒ envoi d’un message via `WebRTCPeerTransport`.
2. Si canal non établi, A crée une offer WebRTC et la publie via signalisation.
3. B reçoit l’offer, génère l’answer, renvoie via signalisation.
4. Les candidats ICE sont échangés via signalisation.
5. Une fois le DataChannel ouvert, les `PeerEnvelope` circulent en P2P.

## 6. Limites et intégration applicative

- Le serveur de signalisation fourni est volontairement minimal (mémoire volatile).
- En production, prévoir:
  - authentification des pairs,
  - contrôle d’accès par room,
  - observabilité (logs/metrics),
  - politique de rétention / nettoyage.
- iOS et Kotlin exposent des contrats prêts à brancher sur le moteur WebRTC natif de l’application (WebRTC.framework / org.webrtc ou équivalent).

## 7. Compatibilité

Cette décision ne casse pas les transports existants (`MemoryPeerTransport` / `LoopbackPeerTransport` / simulation bus).  
Le mode WebRTC devient une option supplémentaire compatible avec le même contrat de protocole.
