"use client";
import { useState, useEffect } from "react";
import { fetcher } from "@/lib/api";

type SurveyItem = {
  item_id: string;
  cve_id: string;
  condition: string;
  narrative_text: string;
};

export default function SurveyPage() {
  const [items, setItems] = useState<SurveyItem[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [raterId, setRaterId] = useState("");
  const [started, setStarted] = useState(false);
  
  const [rating, setRating] = useState<number | null>(null);
  const [wouldAct, setWouldAct] = useState<boolean | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    fetcher("/survey/items?count=5").then(d => setItems(d.items));
  }, []);

  const handleStart = (e: React.FormEvent) => {
    e.preventDefault();
    if (raterId.trim() && items.length > 0) setStarted(true);
  };

  const handleSubmit = async () => {
    if (!rating || wouldAct === null) return;
    setSubmitting(true);
    
    const currentItem = items[currentIndex];
    try {
      await fetcher("/survey/responses", {
        method: "POST",
        body: JSON.stringify({
          item_id: currentItem.item_id,
          cve_id: currentItem.cve_id,
          condition: currentItem.condition,
          rater_id: raterId,
          clarity_rating: rating,
          would_act: wouldAct
        })
      });
      
      setRating(null);
      setWouldAct(null);
      
      if (currentIndex < items.length - 1) {
        setCurrentIndex(prev => prev + 1);
      } else {
        setDone(true);
      }
    } catch (e) {
      alert("Failed to submit response.");
    }
    setSubmitting(false);
  };

  if (items.length === 0) {
    return <div className="p-10 text-center text-gray-500">Loading survey... (Generate narratives first)</div>;
  }

  if (!started) {
    return (
      <div className="max-w-md mx-auto mt-20 bg-white p-8 rounded-xl shadow-sm border border-gray-200">
        <h1 className="text-2xl font-bold text-gray-900 mb-2">Vulnerability Narrative Survey</h1>
        <p className="text-gray-600 text-sm mb-6">
          You will be shown short plain-English narratives about software vulnerabilities. 
          Please rate how clear they are and whether you feel you have enough information to make a decision.
        </p>
        <form onSubmit={handleStart} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Enter your Participant ID</label>
            <input
              type="text"
              required
              value={raterId}
              onChange={e => setRaterId(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
              placeholder="e.g., rater-01"
            />
          </div>
          <button type="submit" className="w-full bg-blue-600 text-white font-medium py-2 rounded-md hover:bg-blue-700">
            Start Survey ({items.length} items)
          </button>
        </form>
      </div>
    );
  }

  if (done) {
    return (
      <div className="max-w-md mx-auto mt-20 bg-white p-8 rounded-xl shadow-sm border border-gray-200 text-center">
        <div className="text-4xl mb-4">🎉</div>
        <h1 className="text-2xl font-bold text-gray-900 mb-2">Thank You!</h1>
        <p className="text-gray-600">Your responses have been recorded.</p>
      </div>
    );
  }

  const currentItem = items[currentIndex];

  return (
    <div className="max-w-2xl mx-auto mt-10">
      <div className="text-sm text-gray-500 font-medium mb-4 text-center">
        Progress: {currentIndex + 1} / {items.length}
      </div>
      
      <div className="bg-white p-8 rounded-xl shadow-sm border border-gray-200 mb-6">
        <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-4">Read the following narrative:</h2>
        <p className="text-lg text-gray-800 leading-relaxed font-serif">
          {currentItem.narrative_text}
        </p>
      </div>

      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200 space-y-8">
        <div>
          <h3 className="text-base font-semibold text-gray-900 mb-3">1. How clear and easy to understand is this narrative?</h3>
          <div className="flex justify-between items-center bg-gray-50 p-2 rounded-lg">
            <span className="text-xs text-gray-500 px-2">Very Confusing</span>
            {[1, 2, 3, 4, 5].map(val => (
              <button
                key={val}
                onClick={() => setRating(val)}
                className={`w-12 h-12 rounded-full font-bold transition-all ${
                  rating === val ? "bg-blue-600 text-white ring-4 ring-blue-100" : "bg-white text-gray-700 border hover:border-blue-400"
                }`}
              >
                {val}
              </button>
            ))}
            <span className="text-xs text-gray-500 px-2">Very Clear</span>
          </div>
        </div>

        <div>
          <h3 className="text-base font-semibold text-gray-900 mb-3">2. Do you feel you have enough information to make a decision or take action?</h3>
          <div className="flex gap-4">
            <button
              onClick={() => setWouldAct(true)}
              className={`flex-1 py-3 rounded-lg font-medium border transition-colors ${
                wouldAct === true ? "bg-green-50 border-green-500 text-green-700" : "bg-white text-gray-700 hover:border-gray-300"
              }`}
            >
              Yes
            </button>
            <button
              onClick={() => setWouldAct(false)}
              className={`flex-1 py-3 rounded-lg font-medium border transition-colors ${
                wouldAct === false ? "bg-red-50 border-red-500 text-red-700" : "bg-white text-gray-700 hover:border-gray-300"
              }`}
            >
              No
            </button>
          </div>
        </div>

        <button
          onClick={handleSubmit}
          disabled={!rating || wouldAct === null || submitting}
          className="w-full bg-blue-600 text-white font-bold py-3 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting ? "Submitting..." : "Next →"}
        </button>
      </div>
    </div>
  );
}
