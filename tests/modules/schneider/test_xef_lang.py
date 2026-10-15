import pytest

from peat.modules.schneider.xef import xef_lang, xef_parse
from peat.parsing.tc6 import TC6

VARIABLES = """
<variables name="A" typeName="BOOL"></variables>
<variables name="B" typeName="BOOL"></variables>
<variables name="Start" typeName="BOOL"></variables>
<variables name="Stop" typeName="BOOL"></variables>
<variables name="Motor" typeName="BOOL"></variables>
<variables name="Btn" typeName="BOOL"></variables>
<variables name="Lamp" typeName="BOOL"></variables>
<variables name="Pulse" typeName="BOOL"></variables>
<variables name="Done" typeName="BOOL"></variables>
<variables name="Go" typeName="BOOL"></variables>
<variables name="Count" typeName="INT"></variables>
<variables name="Level" typeName="REAL"></variables>
<variables name="Sensor" typeName="BOOL" topologicalAddress="%I0.1.2"></variables>
"""


def make_xef(programs: str, variables: str = VARIABLES, tasks: str = "", extra: str = "") -> str:
    if not tasks:
        tasks = '<taskDesc task="MAST" taskType="cyclic" valueType="0"></taskDesc>'
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FEFExchangeFile>
  {extra}
  <dataBlock>{variables}</dataBlock>
  <logicConf><resource>{tasks}</resource></logicConf>
  {programs}
</FEFExchangeFile>"""


def section(name: str, source: str, task: str = "MAST", section_type: str = "section") -> str:
    return f"""<program>
  <identProgram name="{name}" type="{section_type}" task="{task}"></identProgram>
  {source}
</program>"""


def ffb(
    type_name: str,
    instance: str,
    x: int,
    y: int,
    inputs: dict[str, str],
    outputs: dict[str, str],
    en_eno: bool = False,
) -> str:
    def pins(tag: str, params: dict[str, str]) -> str:
        return "".join(
            f'<{tag} invertedPin="false" formalParameter="{name}"'
            + (f' effectiveParameter="{value}"' if value else "")
            + f"></{tag}>"
            for name, value in params.items()
        )

    return f"""<FFBBlock instanceName="{instance}" typeName="{type_name}"
    additionnalPinNumber="0" enEnO="{str(en_eno).lower()}" width="7" height="6">
  <objPosition posX="{x}" posY="{y}"></objPosition>
  <descriptionFFB execAfter="">
    {pins("inputVariable", {"EN": "", **inputs})}
    {pins("outputVariable", {"ENO": "", **outputs})}
  </descriptionFFB>
</FFBBlock>"""


def link(source: str, source_pin: str, dest: str, dest_pin: str) -> str:
    return f"""<linkFB>
  <linkSource parentObjectName="{source}" pinName="{source_pin}">
    <objPosition posX="0" posY="0"></objPosition>
  </linkSource>
  <linkDestination parentObjectName="{dest}" pinName="{dest_pin}">
    <objPosition posX="0" posY="0"></objPosition>
  </linkDestination>
</linkFB>"""


def fbd(*objects: str) -> str:
    network = "".join(objects)
    return f'<FBDSource nbRows="24" nbColumns="36"><networkFBD>{network}</networkFBD></FBDSource>'


def ld(*lines: str) -> str:
    rows = "".join(f"<typeLine>{line}</typeLine>" for line in lines)
    return f'<LDSource nbColumns="11"><networkLD>{rows}</networkLD></LDSource>'


def contact(variable: str, contact_type: str = "openContact") -> str:
    return f'<contact typeContact="{contact_type}" contactVariableName="{variable}"></contact>'


def coil(variable: str, coil_type: str = "coil") -> str:
    return f'<coil typeCoil="{coil_type}" coilVariableName="{variable}"></coil>'


def convert(xef: str) -> tuple[dict, TC6, str]:
    parsed = xef_parse.parse_xef(xef)
    tc6 = TC6("test")
    xef_parse.add_project_to_tc6(parsed, tc6)
    st = tc6.generate_st(tc6.generate_xml_string(openplc=True), openplc=True)
    return parsed, tc6, st


def normalize(st: str) -> str:
    return " ".join(st.split())


def test_st_and_il_sections():
    xef = make_xef(
        section("Main", "<STSource>Lamp := A AND %M3;</STSource>")
        + section("Il", "<ILSource>LD Btn\nST Pulse\n</ILSource>")
    )
    _, _, st = convert(xef)

    assert "PROGRAM Main" in st
    # Direct variables become global variables
    assert "Lamp := A AND PEAT_M3;" in st
    assert "PEAT_M3 : BOOL;" in st
    # IL sections are kept as IL
    assert "PROGRAM Il" in st
    assert "LD Btn" in st
    assert "ST Pulse" in st
    assert "PROGRAM Main_inst WITH MAST : Main;" in st
    assert "PROGRAM Il_inst WITH MAST : Il;" in st
    assert "TASK MAST(INTERVAL := T#20ms,PRIORITY := 1);" in st


def test_fbd_section():
    xef = make_xef(
        section(
            "Logic",
            fbd(
                ffb("AND", ".1", 2, 2, {"IN1": "A", "IN2": "B"}, {"OUT": ""}),
                ffb("TON", "TON_1", 12, 2, {"IN": "", "PT": "t#5s"}, {"Q": "Done", "ET": ""}),
                ffb("RE", ".2", 2, 10, {"IN": "Btn"}, {"OUT": "Pulse"}),
                ffb("ADD_REAL", ".3", 2, 16, {"IN1": "Level", "IN2": "1.5"}, {"OUT": "Level"}),
                ffb("FOO_BAR", ".4", 2, 22, {"IN1": "Count"}, {"OUT": "Count"}),
                ffb("S_SR", "SR_1", 12, 22, {"S1": "Start", "R": "Stop"}, {"Q1": "Motor"}),
                link(".1", "OUT", "TON_1", "IN"),
            ),
        )
    )
    _, _, st = convert(xef)

    # Linked pins
    assert "AND1_OUT := AND(A, B);" in st
    assert "TON_1(IN := AND1_OUT, PT := t#5s);" in st
    assert "Done := TON_1.Q;" in st
    # Instances that aren't declared are declared by the POU
    assert "TON_1 : TON;" in st
    assert "SR_1 : SR;" in st
    # Unity blocks become the equivalent IEC 61131-3 blocks
    assert "PEAT_R_TRIG_1(CLK := Btn);" in st
    assert "Pulse := PEAT_R_TRIG_1.Q;" in st
    assert "ADD4_OUT := ADD(Level, REAL#1.5);" in st
    assert "SR_1(S1 := Start, R := Stop);" in st
    # Unknown library blocks become function blocks that do nothing
    assert "FUNCTION_BLOCK FOO_BAR" in st
    assert "IN1 : INT;" in st
    assert "PEAT_FOO_BAR_2(IN1 := Count);" in st
    assert "Count := PEAT_FOO_BAR_2.OUT;" in st
    # The global variables used are declared external
    assert "VAR_EXTERNAL" in st
    assert "Level : REAL;" in st


def test_ld_section():
    xef = make_xef(
        section(
            "Rungs",
            ld(
                # Seal-in rung: Start OR Motor, AND NOT Stop
                "<shortCircuit>"
                + contact("Start")
                + "<VLink></VLink></shortCircuit>"
                + contact("Stop", "closedContact")
                + '<HLink nbCells="8"></HLink>'
                + coil("Motor"),
                contact("Motor"),
                contact("Btn", "PContact")
                + '<HLink nbCells="9"></HLink>'
                + coil("Lamp", "setCoil"),
                contact("%I0.1.2") + '<HLink nbCells="9"></HLink>' + coil("%Q0.2.0", "notCoil"),
            ),
        )
    )
    _, _, st = convert(xef)

    assert "Motor := NOT(Stop) AND (Motor OR Start);" in st
    assert "R_TRIG1(CLK := Btn);" in st
    assert "IF R_TRIG1.Q THEN" in st
    assert "Lamp := TRUE; (*set*)" in st
    # Direct variables are replaced by the variable at the address, or a new variable
    assert "PEAT_Q0_2_0 := NOT(Sensor);" in st


def test_ld_blocks():
    xef = make_xef(
        section(
            "Blocks",
            ld(
                '<compareBlock width="2"><expression>Level &gt; 5.0</expression></compareBlock>'
                '<HLink nbCells="7"></HLink>'
                '<operateBlock width="2">'
                "<statement>Count := Count + 1;</statement></operateBlock>",
                '<emptyCell nbCells="2"></emptyCell>'
                + ffb("TON", "TON_2", 2, 1, {"IN": "", "PT": "t#3s"}, {"Q": "", "ET": ""}),
                contact("Btn")
                + '<HLink nbCells="1"></HLink><emptyCell nbCells="2"></emptyCell>'
                + '<HLink nbCells="6"></HLink>'
                + coil("Lamp"),
            ),
        )
    )
    _, _, st = convert(xef)

    # Blocks are connected to the grid by the rows of their pins
    assert "TON_2(IN := Btn, PT := t#3s);" in st
    assert "Lamp := TON_2.Q;" in st
    # Operate blocks become function blocks that run the statement
    assert "FUNCTION_BLOCK Blocks_OPERATE1" in st
    assert "Count := Count + 1;" in st
    # Compare blocks pass power when they're true
    assert "PEAT_BLOCKS_OPERATE1_1(EN := (Level > 5.0));" in st


SFC_PROGRAM = """<SFCProgram>
  <identProgram name="Seq" type="section" task="MAST"></identProgram>
  <chartSource name="Chart"><networkSFC>
    <step stepType="initialStep" stepName="Idle">
      <objPosition posX="0" posY="0"></objPosition>
      <action qualifier="NONE">
        <actionName><sectionName>Reset</sectionName></actionName>
        <tValue><tLiteral></tLiteral></tValue>
      </action>
    </step>
    <altBranch width="2" relativePos="0"><objPosition posX="0" posY="1"></objPosition></altBranch>
    <transition>
      <objPosition posX="0" posY="1"></objPosition>
      <transitionCondition invertLogic="false">
        <variableName>Go</variableName>
      </transitionCondition>
    </transition>
    <transition>
      <objPosition posX="1" posY="1"></objPosition>
      <transitionCondition invertLogic="false">
        <sectionName>Empty</sectionName>
      </transitionCondition>
    </transition>
    <step stepType="step" stepName="Fill">
      <objPosition posX="0" posY="2"></objPosition>
      <action qualifier="S"><actionName><variableName>Lamp</variableName></actionName></action>
      <action qualifier="L">
        <actionName><variableName>Pulse</variableName></actionName>
        <tValue><tLiteral>t#2s</tLiteral></tValue>
      </action>
    </step>
    <step stepType="macroStep" stepName="MS_1">
      <objPosition posX="1" posY="2"></objPosition>
    </step>
    <transition>
      <objPosition posX="0" posY="3"></objPosition>
      <transitionCondition invertLogic="true">
        <variableName>Sensor</variableName>
      </transitionCondition>
    </transition>
    <transition><objPosition posX="1" posY="3"></objPosition></transition>
    <altJoint width="2" relativePos="0"><objPosition posX="0" posY="3"></objPosition></altJoint>
    <jumpSFC stepName="Idle"><objPosition posX="0" posY="4"></objPosition></jumpSFC>
  </networkSFC></chartSource>
  <macroSource name="MS_1"><networkSFC>
    <step stepType="inStep" stepName="MS_1_IN"><objPosition posX="0" posY="0"></objPosition></step>
    <transition>
      <objPosition posX="0" posY="1"></objPosition>
      <transitionCondition invertLogic="false">
        <variableName>Done</variableName>
      </transitionCondition>
    </transition>
    <step stepType="outStep" stepName="MS_1_OUT">
      <objPosition posX="0" posY="2"></objPosition>
    </step>
  </networkSFC></macroSource>
  <actionSource name="Reset"><STSource>Count := 0;</STSource></actionSource>
  <transitionSource name="Empty"><STSource>Level &lt; 1.0</STSource></transitionSource>
</SFCProgram>"""


def test_sfc_section():
    _, _, st = convert(make_xef(SFC_PROGRAM))
    st = normalize(st)

    assert "INITIAL_STEP Idle: Reset(N); END_STEP" in st
    assert "ACTION Reset: Count := 0; END_ACTION" in st
    assert "TRANSITION FROM Idle TO Fill := Go; END_TRANSITION" in st
    assert "STEP Fill: Lamp(S); Pulse(L, t#2s); END_STEP" in st
    assert "TRANSITION FROM Fill TO Idle := NOT (Sensor); END_TRANSITION" in st
    # Transition sections in ST become the condition
    assert "TRANSITION FROM Idle TO MS_1_IN := Level < 1.0; END_TRANSITION" in st
    # Macro steps are replaced by their steps
    assert "TRANSITION FROM MS_1_IN TO MS_1_OUT := Done; END_TRANSITION" in st
    # Transitions without a condition are never true
    assert "TRANSITION FROM MS_1_OUT TO Idle := FALSE; END_TRANSITION" in st


def test_tasks_and_special_sections():
    tasks = (
        '<taskDesc task="MAST" taskType="periodic" valueType="50"></taskDesc>'
        '<taskDesc task="FAST" taskType="periodic" valueType="5"></taskDesc>'
    )
    xef = make_xef(
        section("Main", "<STSource>Sub1();</STSource>")
        + section("Quick", "<STSource>Pulse := Btn;</STSource>", task="FAST")
        + section("Sub1", "<STSource>Lamp := A;</STSource>", section_type="SR")
        + """<program>
  <identProgram name="Tick" type="Timer" timeBase="10" preset="25"></identProgram>
  <STSource>Count := Count + 1;</STSource>
</program>
<program>
  <identProgram name="Evt0" type="Evt"></identProgram>
  <STSource>Done := TRUE;</STSource>
</program>""",
        tasks=tasks,
    )
    _, _, st = convert(xef)

    assert "TASK MAST(INTERVAL := T#50ms,PRIORITY := 1);" in st
    assert "TASK FAST(INTERVAL := T#5ms,PRIORITY := 0);" in st
    assert "PROGRAM Quick_inst WITH FAST : Quick;" in st
    # Subroutines become function blocks, called by an instance of the same name
    assert "FUNCTION_BLOCK Sub1_SR" in st
    assert "Sub1 : Sub1_SR;" in st
    assert "Sub1();" in st
    assert "PROGRAM Sub1_inst" not in st
    # Timer sections run every time base * preset
    assert "TASK Tick_TIMER(INTERVAL := T#250ms,PRIORITY := 0);" in st
    assert "PROGRAM Tick_inst WITH Tick_TIMER : Tick;" in st
    # Event sections are converted, but don't run
    assert "PROGRAM Evt0" in st
    assert "Evt0_inst" not in st


def test_reserved_names():
    variables = VARIABLES + '<variables name="Mixer" typeName="Mixer"></variables>'
    dfb = """<FBSource nameOfFBType="Mixer" version="0.01">
  <inputParameters><variables name="IN1" typeName="BOOL"></variables></inputParameters>
  <FBProgram name="Body"><STSource>;</STSource></FBProgram>
</FBSource>"""
    xef = make_xef(
        section("S1", "<STSource>Mixer(IN1 := A);</STSource>")
        + section("Séquence", "<STSource>Lamp := B;</STSource>"),
        variables=variables,
        extra=dfb,
    )
    _, _, st = convert(xef)

    # Names of library blocks and variables can't be used for POUs
    assert "PROGRAM S1_SECTION" in st
    assert "FUNCTION_BLOCK Mixer_DFB" in st
    assert "Mixer : Mixer_DFB;" in st
    # POU names are ASCII
    assert "PROGRAM Sequence" in st


def test_repair_tc6(caplog):
    xef = make_xef(
        section("Logic", fbd(ffb("AND", ".1", 2, 2, {"IN1": "A", "IN2": "B"}, {"OUT": "Lamp"})))
        + section("Other", "<STSource>Pulse := Btn;</STSource>")
    )
    _, tc6, _ = convert(xef)
    for block in tc6.pous[0].iter("block"):
        block.set("typeName", "NOT_A_BLOCK")

    xef_parse.repair_tc6(tc6, {"Logic"})
    st = tc6.generate_st(tc6.generate_xml_string(openplc=True), openplc=True)

    assert "Logic couldn't be converted to Structured Text" in caplog.text
    assert "(* PEAT couldn't convert this logic:" in st
    assert "PEAT_NO_ST_LOGIC := TRUE;" in st
    assert "Pulse := Btn;" in st


def test_serializable():
    parsed = xef_parse.parse_xef(make_xef(SFC_PROGRAM))
    assert "element" in parsed["sections"][0]

    serialized = xef_parse.serializable(parsed)
    assert "element" not in serialized["sections"][0]
    assert serialized["sections"][0]["language"] == "SFC"
    # The original isn't modified
    assert "element" in parsed["sections"][0]


@pytest.mark.parametrize(
    ("name", "expected"),
    [("Valve", "Valve"), ("Séquence", "Sequence"), ("1st step", "S_1st_step"), ("a-b", "a_b")],
)
def test_sanitize_name(name, expected):
    assert xef_lang.sanitize_name(name) == expected


def test_unique_name():
    taken = {"motor"}
    assert xef_lang.unique_name("Motor", taken, "_SR") == "Motor_SR"
    assert xef_lang.unique_name("TON", taken, "_DFB") == "TON_DFB"
    assert xef_lang.unique_name("Pump", taken, "_SR") == "Pump"
    assert {"motor_sr", "ton_dfb", "pump"} <= taken


@pytest.mark.parametrize(
    ("type_name", "expected_name", "expected_kind"),
    [
        ("AND", "AND", "function"),
        ("ADD_REAL", "ADD", "function"),
        ("RE", "R_TRIG", "functionBlock"),
        ("FE", "F_TRIG", "functionBlock"),
        ("S_SR", "SR", "functionBlock"),
        ("TON", "TON", "functionBlock"),
        ("WRITE_INPUT_INT", "MOVE", "function"),
        ("Mixer", "Mixer", "functionBlock"),
    ],
)
def test_block_library_resolve(type_name, expected_name, expected_kind):
    library = xef_lang.BlockLibrary({"Mixer"}, {})
    spec = library.resolve(type_name)
    assert spec.type_name == expected_name
    assert spec.kind == expected_kind


def test_block_library_set_reset():
    library = xef_lang.BlockLibrary(set(), {})
    assert library.resolve("SET").coil_storage == "set"
    assert library.resolve("RESET").coil_storage == "reset"
