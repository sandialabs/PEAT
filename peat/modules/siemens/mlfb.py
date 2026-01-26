def decode_mlfb(mlfb: str) -> dict[str, str]:
    """
    Decodes the Maschinenlesbare Fabrikatebezeichnung,
    which is German for ``Machine-Readable Product Designation``.
    """

    nominal_current = {
        "1": "Iph=1A, Ignd=1A/Sensitive",
        "2": "Iph=1A, Ignd=Sensitive",
        "5": "Iph=5A, Ignd=5A/Sensitive",
        "6": "Iph=5A, Ignd=Sensitive",
        "7": "Iph=5A, Ignd=1A",
    }

    power_supply = {
        "2": "DC 24v...48v Binary Input Preset 19",
        "4": "DC 60v...125v Binary Input Preset 19",
        "5": "DC 110v...250v Binary Input Preset 73",
        "6": "AC 230v Binary Input Preset 73",
    }

    housing = {
        "B": "Surface mounting case",
        "D": "Flush mounting case, plug in contacts",
        "E": "Flush mounting case, ring lugs",
    }

    lang_region = {
        "A": "DE 50Hz German",
        "B": "World 50/60Hz English",
        "C": "US 60Hz US-English",
        "D": "FR 50/60Hz French",
        "E": "World 50/60Hz Spanish",
        "M": "DE 50Hz German only",
        "N": "World 50/60Hz English only",
        "P": "US 60Hz US-English only",
        "Q": "FR 50/60Hz French only",
        "R": "World 50/60Hz Spanish only",
    }

    systemport = {
        "0": "NO",
        "1": "IEC 60870-5-103 RS232",
        "2": "IEC 60870-5-103 RS485",
        "3": "IEC 60870-5-103 Fiber 820nm",
        "4": "Profibus FMS Slave RS485",
        "5": "Profibus FMS Slave Fiber single loop ST",
        "6": "Profibus FMS Slave Fiber double loop St",
        "9": "Additional protocols, see extension L",
    }

    serviceport = {
        "0": "NO",
        "1": "Digsi 4/Modem RS232",
        "2": "Digsi 4/Modem/RTD-Box RS485",
        "3": "Digsi 4/Modem Fiber 820nm, ST-Conn RTD-Box",
    }

    osc_fault_rec_meter = {
        "1": "Oscillographic Fault Recording",
        "3": "Osc. Fault. Rec. & min/max/dmd measure",
    }

    overcurrent_motorprotection = {
        "B": "50(N) 51(N)",
        "F": "50(N) 51(N) 46, 49, 4 Setting group",
        "H": "50(N) 51(N) 46, 49, 4 Motor protection",
        "P": "50(N) 51(N) 46, 49, 4 Interim e f",
        "R": "50(N) 51(N) 46, 49, 4 IEF, motor",
    }

    dir_overcurr_volt = {"A": "NONE", "B": "Sensitive Ground Fault"}

    auto_reclose_fault_loc = {"0": "NONE", "1": "79 Auto Reclose"}

    mlfb_vals = [
        nominal_current,
        power_supply,
        housing,
        lang_region,
        systemport,
        serviceport,
        osc_fault_rec_meter,
        overcurrent_motorprotection,
        dir_overcurr_volt,
        auto_reclose_fault_loc,
    ]

    mlfb_val_names = [
        "nominal_current",
        "power_supply",
        "housing",
        "lang_region",
        "systemport",
        "serviceport",
        "osc_fault_rec_meter",
        "overcurrent_motorprotection",
        "dir_overcurr_volt",
        "auto_reclose_fault_loc",
    ]

    mlfb_data = {"mlfb": mlfb}

    for idx, c in enumerate(mlfb):
        mlfb_data[mlfb_val_names[idx]] = mlfb_vals[idx].get(c, "N/A")

    return mlfb_data
