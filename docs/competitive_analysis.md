# ניתוח מתחרים: AgentGuard

**תאריך:** 15.10.2026
**מקורות:** דוח "Agentic Wallets… Israel and Global Market Map" מ־13.10.2026, ובדיקה ישירה של שלוש טענות מרכזיות מולם מקורות ראשוניים.

> **אזהרה לגבי המקור:** הדוח נוצר ב־ChatGPT. כל הקישורים בו מסומנים `utm_source=chatgpt.com`, ונשאר בו סימן ציטוט שלא עבר עיבוד (`fileciteturn0file0`). רוב הטענות בו נשענות על פוסטים ב־LinkedIn ועל חומר שיווקי. צריך להתייחס אליו כמפה ראשונית, לא כעובדות.

## 1. מה נבדק ישירות

| טענה בדוח | מקור ראשוני | סטטוס |
|---|---|---|
| ה־README של Coinbase AgentKit מזהיר מ־prompt injection ומציין שאין בו spend caps, allowlist או אישור אנושי | [github.com/coinbase/agentkit](https://github.com/coinbase/agentkit), סעיף "Managing Risk" | **אומת.** כתוב שם במפורש ש־AgentKit "does not gate transfers behind human approval, enforce spend caps, or allowlist destinations" |
| ל־CyVers יש Pre-Transaction Firewall ו־Secure Co-Signer | [cyvers.ai](https://cyvers.ai/) | **אומת.** האתר מציין גם זיהוי address poisoning, שילוב עם Safe, Fireblocks ו־MPC, ומדיניות drag-and-drop |
| CyVers מאמתת את ה־"intent, context, anomalies" של סוכני AI | פוסט LinkedIn לפי הדוח | **לא אומת.** הנושא לא מופיע באתר. ה־"Agentic AI" של CyVers הוא סוכנים שעובדים *עבור* הלקוח, לא הגנה *על* סוכנים |
| ל־Blockaid יש Cosigner, היא עובדת עם סוכנים, ומשולבת ב־Fordefi, Utila ו־Bankr | [בלוג Blockaid](https://blockaid.io/blog/how-to-build-smarter-safer-onchain-ai-agents-with-blockaid), [Bankr](https://blockaid.io/blog/blockaid-expands-protection-to-the-bankr-experience) | **אומת חלקית.** יש להם Transaction Scanning API לסוכנים והשילובים קיימים. הפוסט מאוקטובר 2026 על prompt injection במטא־דאטה של טוקנים לא אומת |

## 2. מיפוי מול שבע שאלות המחקר מה־brief

מקרא: ✅ קיים (מאומת) · 🟡 נטען אבל לא מאומת · ❌ לא נמצא · ? לא ידוע

| שאלה | Blockaid | CyVers | Coinbase AgentKit / Agentic Wallets | Openfort / Cobo / Crossmint | **AgentGuard (Phase 1)** |
|---|---|---|---|---|---|
| 1. מזהה חריגה מכוונת המשתמש? | 🟡 | 🟡 | ❌ ב־SDK, ובמוצר המנוהל יש spending guardrails | 🟡 ב־Cobo "Pact" וב־Crossmint/Mastercard "Verifiable Intent" | ✅ ברמת יעד, סכום, טוקן ורשת. סמנטיקה (Scenario B) עוד לא נבנתה |
| 2. בודק מאיפה הגיעה הוראה שמקורה בתוכן חיצוני? | 🟡 טענה לגבי מטא־דאטה של טוקנים | ❌ | ❌ ורק מזהירים | ❌ | ✅ provenance ו־untrusted-by-default |
| 3. אפשר לעקוף את הבקרה? | co-signer, קשה לעקוף | co-signer, קשה לעקוף | ב־SDK כן | חוזה חכם או policy, קשה לעקוף | **כן. אין אכיפה**, זה רק מנוע החלטה |
| 4. מנתח רצף של עסקאות? | ? | ✅ ניטור תזרים | ? | ✅ spend policies ותקציבים | ❌ מתוכנן ל־Phase 2 |
| 5. מסביר ומציג ראיות? | ? | ? | ? | ? | ✅ reason codes, evidence ו־audit chain |
| 6. מה נדרש כדי לשלב? | API ו־Cosigner | API, plug-in ל־MPC | SDK | SDK | API מקומי בלבד |
| 7. איזו בעיה לא פתורה? | ראו סעיף 3 | | | | |

## 3. מסקנות

**עובדות:**
1. **Scenario A לבדו אינו בידול.** allowlist ליעדים קיים כבר ב־Openfort, Cobo, Crossmint ובמוצר המנוהל של Coinbase. זיהוי address poisoning קיים כבר ב־CyVers. Phase 1 הוא תשתית טובה, אבל הוא לא המוצר.
2. **הבעיה אמיתית ומתועדת מצד הספקים עצמם.** Coinbase כותבת במפורש שה־SDK הפתוח לא מגן, וממליצה על guardrails בשכבת האפליקציה. זה בדיוק המקום של AgentGuard.
3. **אכיפה בנקודת החתימה (co-signer) כבר קיימת** אצל Blockaid ו־CyVers. מנוע החלטה בלי אכיפה לא יתחרה בהם.

**השערות שעדיין פתוחות:**
- **החלל הלבן לפי הדוח:** קשירה *קריפטוגרפית* של המנדט האנושי לעסקה הסופית, בלי תלות בספק ארנק מסוים, יחד עם תיעוד פורנזי של השאלה "למה הסוכן שילם". הדוח מעריך שזו ההזדמנות הכי גבוהה. זו הערכה של הדוח, לא עובדה.
- Blockaid ו־CyVers מתקדמות בדיוק לכיוון הזה. חלון הזמן כנראה קצר.

## 4. השפעה על תוכנית העבודה

| לפני | אחרי (מומלץ) |
|---|---|
| Phase 2 = היסטוריה ופיצול תשלומים | **Phase 2 = Signed Mandate + תקציב מצטבר ופיצול.** המשתמש חותם על מנדט מובנה: נכס, תקרה יומית, יעדים, מטרה ותוקף. המנוע מאמת את החתימה ואוכף את הכללים גם על רצף של עסקאות. כך נסגרת גם החולשה המרכזית של Phase 1, שבה הקלט "המהימן" לא מוגן. |
| Phase 4 = Testnet | **להקדים:** red-team על Coinbase AgentKit ב־Base Sepolia (P0 בדוח). זה הניסוי שיכול להוכיח או להפריך את הערך: סוכן אמיתי, הזרקה אמיתית ו־AgentGuard כ־sidecar לפני החתימה. אין שימוש בכסף אמיתי. |
| שיחות לקוחות "בסוף" | השאלה שצריך לשאול לקוחות כבר מנוסחת: *"כשסוכן AI יוזם תשלום, האם הארנק הנוכחי שלכם יכול להוכיח שהעסקה החתומה עדיין תואמת את הכוונה המקורית, אחרי שהסוכן קרא תוכן לא מהימן?"* |
