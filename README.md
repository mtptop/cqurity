# CQurity — Automated Code Auditor

CQurity არის უახლესი თაობის სტატიკური კოდის ანალიზის (SAST) და ავტომატიზირებული რეპარაციის (Auto-Remediation) 
სისტემა, რომელიც დაფუძნებულია უახლეს **Llama 4 Scout** მოდელზე Groq Cloud ინფრასტრუქტურის გავლით.

## ძირითადი ფუნქციონალი
- **Hierarchical Tree Parsing:** ატვირთული ZIP არქივების დინამიკური ასახვა გვერდითა პანელში.
- **Analytical Dependency Mapping:** ფაილთაშორისი კავშირების ანალიზი დამოკიდებულებების წესებზე დაყრდნობით.
- **Context-Optimized Batching:** Greedy Bin-Packing ალგორითმი ტოკენების დაზოგვისა და დიდი ფაილების დამუშავებისთვის.
- **Three-Tier Vulnerability Reports:** მოწყვლადობის იდენტიფიცირება, დაზიანებული ხაზების ექსტრაქცია და მზა უსაფრთხო კოდის (Patch) გენერაცია.

## ტექნოლოგიური სტეკი
- **Frontend/Core UI:** Streamlit Framework
- **AI Inference Engine:** meta-llama/llama-4-scout-17b-16e-instruct (Via Groq SDK)
- **Language Stack:** Python 3.9+
