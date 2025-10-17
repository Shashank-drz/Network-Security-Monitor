#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>
#include <unordered_map>
#include <variant>
#include <algorithm>
#include <random>
#include <array>
#include <iomanip>
#include <cstdint>

#include "nlohmann/json.hpp"
#include "yaml-cpp/yaml.h"

using json = nlohmann::json;

using RuleValue = std::variant<std::string, double>;

struct SimpleCondition { std::string key; std::string op; RuleValue value; };
struct SequenceCondition { std::vector<std::string> rule_names; int time_window_seconds; };

using AllOfCondition = std::vector<SimpleCondition>;
using Condition = std::variant<SimpleCondition, SequenceCondition, AllOfCondition>;

struct RecentEvent { std::string rule_name; std::chrono::system_clock::time_point timestamp; };

static std::string uuid_v4() {
    std::random_device rd; std::mt19937 gen(rd()); std::uniform_int_distribution<uint32_t> dis(0, 0xffffffff);
    std::array<uint8_t, 16> b{}; for (int i = 0; i < 16; i += 4) { uint32_t r = dis(gen); b[i]=r>>24; b[i+1]=(r>>16)&0xFF; b[i+2]=(r>>8)&0xFF; b[i+3]=r&0xFF; }
    b[6] = (b[6] & 0x0F) | 0x40; b[8] = (b[8] & 0x3F) | 0x80;
    std::ostringstream o; o << std::hex << std::setfill('0'); for (int i=0;i<16;++i){ o<<std::setw(2)<<int(b[i]); if(i==3||i==5||i==7||i==9) o<<'-'; } return o.str();
}

static std::string now_iso8601() {
    auto n=std::chrono::system_clock::now(); auto t=std::chrono::system_clock::to_time_t(n);
    auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(n.time_since_epoch())%1000;
    std::tm tm{}; gmtime_r(&t,&tm);
    std::ostringstream o; o<<std::put_time(&tm,"%Y-%m-%dT%H:%M:%S")<<'.'<<std::setfill('0')<<std::setw(6)<<(ms.count()*1000)<<"+0000"; return o.str();
}

class Rule {
public: Rule(std::string n, Condition c):name_(std::move(n)),cond_(std::move(c)){} const std::string& Name()const{return name_;} const Condition& Cond()const{return cond_;}
private: std::string name_; Condition cond_;
};

class Engine {
public:
    void LoadRules(const std::string& path) {
        YAML::Node cfg = YAML::LoadFile(path);
        for (const auto& rn : cfg["rules"]) {
            std::string name = rn["name"].as<std::string>();
            if (rn["condition"]) rules_.emplace_back(name, ParseCond(rn["condition"].as<std::string>()));
            else if (rn["sequence"]) {
                SequenceCondition s; s.time_window_seconds = rn["sequence"]["time_window"].as<int>();
                for (auto& x : rn["sequence"]["rules"]) s.rule_names.push_back(x.as<std::string>());
                rules_.emplace_back(name, s);
            }
        }
        std::cerr << "[INFO] Loaded " << rules_.size() << " rules.\n";
    }

    void ProcessEvent(const std::string& line, std::ofstream& out) {
        try {
            json ev = json::parse(line);
            if (ev.value("event_type","") != "alert") return;
            for (const auto& r : rules_) {
                bool matched=false;
                if (std::holds_alternative<SimpleCondition>(r.Cond())) matched = EvalSimple(std::get<SimpleCondition>(r.Cond()), ev);
                else if (std::holds_alternative<AllOfCondition>(r.Cond())) matched = EvalAll(std::get<AllOfCondition>(r.Cond()), ev);
                if (matched) {
                    json f; f["timestamp"]=now_iso8601(); if (ev.contains("timestamp")) f["original_timestamp"]=ev["timestamp"];
                    f["rule_name"]=r.Name(); f["original_event"]=ev; f["correlation_id"]=uuid_v4();
                    out << f.dump() << std::endl; out.flush();
                    EvalSeq(r.Name(), ev, out);
                }
            }
            Cleanup();
        } catch (const json::parse_error&) {}
    }

    std::streampos get_pos() const { return last_pos_; }
    void set_pos(std::streampos p){ last_pos_=p; }

private:
    static RuleValue ParseVal(const std::string& v){ if(v.size()>=2 && v.front()=='"' && v.back()=='"') return v.substr(1,v.size()-2); try{return std::stod(v);}catch(...){return v;} }
    static SimpleCondition ParseSimple(const std::string& s){
        static const std::vector<std::string> ops={"==","!=",">=","<=" ,">","<"};
        size_t pos=std::string::npos; std::string op; for (auto& o:ops){ pos=s.find(o); if(pos!=std::string::npos){ op=o; break; } }
        if(pos==std::string::npos) throw std::runtime_error("bad cond");
        auto trim=[](std::string& x){ x.erase(0,x.find_first_not_of(" \t\n\r")); x.erase(x.find_last_not_of(" \t\n\r")+1); };
        std::string k=s.substr(0,pos), v=s.substr(pos+op.size()); trim(k); trim(v); return {k,op,ParseVal(v)};
    }
    static Condition ParseCond(const std::string& raw){
        std::vector<std::string> parts; size_t st=0; while(true){ auto p=raw.find(" and ",st); if(p==std::string::npos){ parts.emplace_back(raw.substr(st)); break;} parts.emplace_back(raw.substr(st,p-st)); st=p+5; }
        if(parts.size()==1) return ParseSimple(parts[0]); AllOfCondition all; for(auto& p:parts) all.emplace_back(ParseSimple(p)); return all;
    }
    static bool json_get(const json& o,const std::string& path,json& out){
        try{ const json* cur=&o; size_t st=0; while(st<path.size()){ auto d=path.find('.',st); std::string k=(d==std::string::npos)?path.substr(st):path.substr(st,d-st); if(!cur->contains(k)) return false; cur=&cur->at(k); if(d==std::string::npos) break; st=d+1; } out=*cur; return true; }catch(...){return false;}
    }
    static bool EvalSimple(const SimpleCondition& c, const json& ev){
        json v; if(!json_get(ev,c.key,v)) return false;
        if(std::holds_alternative<std::string>(c.value)){ if(!v.is_string()) return false; const auto& rv=std::get<std::string>(c.value); const auto& av=v.get_ref<const std::string&>();
            if(c.op=="==") return av==rv; if(c.op=="!=") return av!=rv; return false;
        } else { if(!v.is_number()) return false; double rv=std::get<double>(c.value), av=v.get<double>();
            if(c.op=="==") return av==rv; if(c.op=="!=") return av!=rv; if(c.op==">") return av>rv; if(c.op=="<") return av<rv; if(c.op==">=") return av>=rv; if(c.op=="<=") return av<=rv; return false; }
    }
    static bool EvalAll(const AllOfCondition& a, const json& ev){ for(const auto& c:a) if(!EvalSimple(c,ev)) return false; return true; }
    void EvalSeq(const std::string& matched, const json& ev, std::ofstream& out){
        if(!ev.contains("src_ip")) return; std::string ip = ev["src_ip"]; auto now=std::chrono::system_clock::now(); state_[ip].push_back({matched,now});
        for (const auto& r : rules_) {
            if(!std::holds_alternative<SequenceCondition>(r.Cond())) continue; const auto& s=std::get<SequenceCondition>(r.Cond()); auto& rec=state_[ip];
            if(rec.size() < s.rule_names.size()) continue; bool ok=true; size_t off=rec.size()-s.rule_names.size();
            for(size_t i=0;i<s.rule_names.size();++i){ if(rec[off+i].rule_name!=s.rule_names[i]){ ok=false; break; } }
            if(ok){ auto secs=std::chrono::duration_cast<std::chrono::seconds>(now - rec[off].timestamp).count(); if(secs<=s.time_window_seconds){
                    json f; f["timestamp"]=now_iso8601(); if(ev.contains("timestamp")) f["original_timestamp"]=ev["timestamp"]; f["rule_name"]=r.Name(); f["original_event"]=ev; f["correlation_id"]=uuid_v4();
                    out<<f.dump()<<std::endl; out.flush(); rec.clear(); } }
        }
    }
    void Cleanup(){
        static auto last=std::chrono::system_clock::now(); auto n=std::chrono::system_clock::now(); if(std::chrono::duration_cast<std::chrono::seconds>(n-last).count()<60) return;
        int maxw=0; for(const auto& r:rules_) if(std::holds_alternative<SequenceCondition>(r.Cond())) maxw=std::max(maxw,std::get<SequenceCondition>(r.Cond()).time_window_seconds);
        for(auto& kv:state_){ auto& v=kv.second; v.erase(std::remove_if(v.begin(),v.end(),[n,maxw](const RecentEvent& e){ return std::chrono::duration_cast<std::chrono::seconds>(n-e.timestamp).count()>maxw; }), v.end()); }
        last=n;
    }

    std::vector<Rule> rules_;
    std::unordered_map<std::string, std::vector<RecentEvent>> state_;
    std::streampos last_pos_ = 0;
};

static bool file_exists(const std::string& p){ std::ifstream f(p); return f.good(); }

static void Monitor(const std::string& path, Engine& eng, std::ofstream& out){
    std::string in = path;
    if (in.size() < 5 || in.substr(in.size()-5)!=".json"){ if(!in.empty() && in.back()=='/') in.pop_back(); in += "/eve.json"; }
    while(!file_exists(in)) std::this_thread::sleep_for(std::chrono::seconds(2));
    std::ifstream s(in); while(!s.is_open()){ std::this_thread::sleep_for(std::chrono::seconds(2)); s.open(in); }
    if(eng.get_pos()>0){ s.seekg(eng.get_pos()); if(s.fail()){ s.clear(); s.seekg(0); } }
    while(true){
        std::string line; while(std::getline(s,line)){ eng.ProcessEvent(line,out); }
        if(s.eof()){ auto pos=s.tellg(); if(pos!=(std::streampos)-1) eng.set_pos(pos); s.clear(); }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) return 1;
    std::string rules_path = argv[1];
    std::string eve_in     = argv[2];
    std::string out_path   = argv[3];
    if (out_path.size() < 5 || out_path.substr(out_path.size()-5) != ".json"){ if(!out_path.empty() && out_path.back()=='/') out_path.pop_back(); out_path += "/findings.json"; }

    Engine engine;
    try { engine.LoadRules(rules_path); } catch (...) { return 1; }

    std::ofstream out(out_path, std::ios_base::app);
    if (!out.is_open()) return 1;

    Monitor(eve_in, engine, out);
    return 0;
}
