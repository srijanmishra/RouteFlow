#ifndef __INSTRUCTION_HH__
#define __INSTRUCTION_HH__

#include "TLV.hh"


enum InstructionType {
    RFIT_METER = 1,              /* Meter id */
    RFIT_APPLY_ACTIONS = 2,      /* Apply actions */
    RFIT_CLEAR_ACTIONS = 3,      /* Clear actions */
    RFIT_WRITE_ACTIONS = 4,      /* Write actions */
    RFIT_WRITE_METADATA = 5,     /* Write metadata */
    RFIT_GO_TABLE = 6,           /* Go to table */
};

class Instruction : public TLV {
    public:
        Instruction(const Instruction& other);
        Instruction(InstructionType, boost::shared_array<uint8_t> value);
        Instruction(InstructionType, const uint8_t* value);
        Instruction(InstructionType, const uint32_t value);

        Instruction& operator=(const Instruction& other);
        bool operator==(const Instruction& other);
        virtual std::string type_to_string() const;
        virtual mongo::BSONObj to_BSON() const;

        static Instruction* from_BSON(mongo::BSONObj);
    private:
        static size_t type_to_length(uint8_t);
        static byte_order type_to_byte_order(uint8_t);
};

namespace InstructionList {
    mongo::BSONArray to_BSON(const std::vector<Instruction> list);
    std::vector<Instruction> to_vector(std::vector<mongo::BSONElement> array);
}

#endif /* __INSTRUCTION_HH__ */
